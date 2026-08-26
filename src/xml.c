int saml_doc_validate(xmlDoc* doc) {
  return xmlSchemaValidateDoc(XML_SCHEMA_VALIDATE_CTX, doc) == 0 ? 1 : 0;
}


static xmlXPathObject* eval_xpath(xmlDoc* doc, xmlXPathCompExpr* xpath) {
  xmlXPathContext* ctx = xmlXPathNewContext(doc);
  if (ctx == NULL) {
    return NULL;
  }

  if (xmlXPathRegisterNs(ctx, (xmlChar*)"saml", (xmlChar*)SAML_XMLNS_ASSERTION) < 0) {
    xmlXPathFreeContext(ctx);
    return NULL;
  }

  if (xmlXPathRegisterNs(ctx, (xmlChar*)"samlp", (xmlChar*)SAML_XMLNS_PROTOCOL) < 0) {
    xmlXPathFreeContext(ctx);
    return NULL;
  }

  xmlXPathObject* obj = xmlXPathCompiledEval(xpath, ctx);
  xmlXPathFreeContext(ctx);
  return obj;
}


static int is_saml_assertion(xmlNode* node) {
  return node->type == XML_ELEMENT_NODE &&
    xmlStrEqual(node->name, (const xmlChar*)"Assertion") == 1 &&
    node->ns != NULL &&
    xmlStrEqual(node->ns->href, (const xmlChar*)SAML_XMLNS_ASSERTION) == 1;
}


// The direct child of node named name in namespace ns, or NULL. Only direct
// children: an element the message itself declares is not the same as one a
// document-wide search happens to reach first.
static xmlNode* ns_child(xmlNode* node, const xmlChar* name, const char* ns) {
  for (xmlNode* child = node->children; child != NULL; child = child->next) {
    if (child->type == XML_ELEMENT_NODE &&
        xmlStrEqual(child->name, name) == 1 &&
        child->ns != NULL &&
        xmlStrEqual(child->ns->href, (const xmlChar*)ns) == 1) {
      return child;
    }
  }
  return NULL;
}


// The text of node's own Issuer child, or NULL. Issuer is in the assertion
// namespace wherever it appears, so a look-alike in another one is not it.
static xmlChar* issuer_of(xmlDoc* doc, xmlNode* node) {
  xmlNode* issuer = ns_child(node, (const xmlChar*)"Issuer", SAML_XMLNS_ASSERTION);
  return issuer == NULL ? NULL : xmlNodeListGetString(doc, issuer->children, 1);
}


// A Response's issuer is read from its assertion, the element the identity
// itself comes from. The Response's own Issuer sits outside an assertion-level
// signature and can be rewritten without breaking it, while every top-level
// assertion still in the document is one the signature covers. A message that
// carries no assertion is only accepted signed whole, so its own Issuer is the
// one to read.
//
// Like the other accessors, this expects a document one of the two verify paths
// let through, and each path keeps that property its own way: the POST binding
// by pruning what the signature leaves out, the redirect binding by signing the
// encoded message whole and never pruning at all. Narrowing either one is what
// would cost this its footing.
xmlChar* saml_doc_issuer(xmlDoc* doc) {
  xmlNode* root = xmlDocGetRootElement(doc);
  if (root == NULL) {
    return NULL;
  }

  if (xmlStrEqual(root->name, (const xmlChar*)"Response") == 1) {
    for (xmlNode* child = root->children; child != NULL; child = child->next) {
      if (is_saml_assertion(child)) {
        return issuer_of(doc, child);
      }
    }
    return NULL;
  }

  return issuer_of(doc, root);
}


void saml_issuers_free(xmlChar** issuers, size_t issuers_len) {
  for (size_t i = 0; i < issuers_len; i++) {
    xmlFree(issuers[i]);
  }
  free(issuers);
}


// Every issuer the message attributes content to: one per top-level assertion
// of a Response, or its own for a message that carries none and is therefore
// only accepted signed whole. A caller matching
// the issuer against a policy has to weigh all of them, because doc_attrs reads
// every top-level assertion and doc_name_id the first one carrying a subject.
// An assertion with no Issuer is invalid SAML; it is listed as an empty string,
// which no configured issuer matches.
int saml_doc_issuers(xmlDoc* doc, xmlChar*** issuers, size_t* issuers_len) {
  *issuers = NULL;
  *issuers_len = 0;

  xmlNode* root = xmlDocGetRootElement(doc);
  if (root == NULL) {
    return 0;
  }

  if (xmlStrEqual(root->name, (const xmlChar*)"Response") != 1) {
    xmlChar* issuer = issuer_of(doc, root);
    if (issuer == NULL) {
      return 0;
    }
    *issuers = malloc(sizeof(xmlChar*));
    if (*issuers == NULL) {
      xmlFree(issuer);
      return -1;
    }
    (*issuers)[0] = issuer;
    *issuers_len = 1;
    return 0;
  }

  size_t count = 0;
  for (xmlNode* child = root->children; child != NULL; child = child->next) {
    if (is_saml_assertion(child)) {
      count++;
    }
  }
  if (count == 0) {
    return 0;
  }

  *issuers = malloc(count * sizeof(xmlChar*));
  if (*issuers == NULL) {
    return -1;
  }

  size_t i = 0;
  for (xmlNode* child = root->children; child != NULL && i < count; child = child->next) {
    if (!is_saml_assertion(child)) {
      continue;
    }
    xmlChar* issuer = issuer_of(doc, child);
    if (issuer == NULL) {
      issuer = xmlStrdup((const xmlChar*)"");
    }
    if (issuer == NULL) {
      // a short list would read as fewer assertions to vouch for than the
      // document holds, so report the failure rather than an incomplete answer
      saml_issuers_free(*issuers, i);
      *issuers = NULL;
      return -1;
    }
    (*issuers)[i++] = issuer;
  }
  *issuers_len = i;
  return 0;
}


xmlChar* saml_doc_name_id(xmlDoc* doc) {
  xmlNode* node = xmlDocGetRootElement(doc);
  if (node == NULL) {
    return NULL;
  }

  if (xmlStrEqual(node->name, (xmlChar*)"LogoutRequest") == 1) {
    // the subject the request names, which the schema puts directly under it
    node = ns_child(node, (const xmlChar*)"NameID", SAML_XMLNS_ASSERTION);
    if (node == NULL) {
      return NULL;
    }
    return xmlNodeListGetString(doc, node->children, 1);
  } else if (xmlStrEqual(node->name, (xmlChar*)"Response") == 1) {
    xmlXPathObject* obj = eval_xpath(doc, XPATH_NAME_ID);
    if (obj == NULL || xmlXPathNodeSetIsEmpty(obj->nodesetval)) {
      xmlXPathFreeObject(obj);
      return NULL;
    }

    xmlNode* node = obj->nodesetval->nodeTab[0];
    if (node->type != XML_ELEMENT_NODE) {
      xmlXPathFreeObject(obj);
      return NULL;
    }

    xmlChar* content = xmlNodeListGetString(doc, node->children, 1);
    xmlXPathFreeObject(obj);
    return content;
  } else {
    return NULL;
  }
}


xmlChar* saml_doc_status_code(xmlDoc* doc) {
  // Read the top-level message's status directly, not a document-wide match:
  // a nested Response (for example inside saml:Advice) can precede the root
  // Status in document order and must not be mistaken for it.
  xmlNode* root = xmlDocGetRootElement(doc);
  if (root == NULL) {
    return NULL;
  }
  xmlNode* status = ns_child(root, (const xmlChar*)"Status", SAML_XMLNS_PROTOCOL);
  if (status == NULL) {
    return NULL;
  }
  xmlNode* code = ns_child(status, (const xmlChar*)"StatusCode", SAML_XMLNS_PROTOCOL);
  if (code == NULL) {
    return NULL;
  }
  // Value is an unqualified attribute; do not match a namespaced look-alike.
  return xmlGetNoNsProp(code, (const xmlChar*)"Value");
}

xmlChar* saml_doc_session_expires(xmlDoc* doc) {
  xmlNode* node = xmlDocGetRootElement(doc);
  if (node == NULL) {
    return NULL;
  }

  if (xmlStrEqual(node->name, (xmlChar*)"Response") == 1) {
    xmlXPathObject* obj = eval_xpath(doc, XPATH_SESSION_EXPIRES);
    if (obj == NULL || xmlXPathNodeSetIsEmpty(obj->nodesetval)) {
      xmlXPathFreeObject(obj);
      return NULL;
    }

    xmlNode* node = obj->nodesetval->nodeTab[0];
    if (node->type != XML_ATTRIBUTE_NODE) {
      xmlXPathFreeObject(obj);
      return NULL;
    }

    xmlChar* content = xmlNodeListGetString(doc, node->children, 1);
    xmlXPathFreeObject(obj);
    return content;
  } else {
    return NULL;
  }
}

xmlChar* saml_doc_session_index(xmlDoc* doc) {
  xmlNode* node = xmlDocGetRootElement(doc);
  if (node == NULL) {
    return NULL;
  }

  if (xmlStrEqual(node->name, (xmlChar*)"LogoutRequest") == 1) {
    node = ns_child(node, (const xmlChar*)"SessionIndex", SAML_XMLNS_PROTOCOL);
    if (node == NULL) {
      return NULL;
    }
    return xmlNodeListGetString(doc, node->children, 1);
  } else if (xmlStrEqual(node->name, (xmlChar*)"Response") == 1) {
    xmlXPathObject* obj = eval_xpath(doc, XPATH_SESSION_INDEX);
    if (obj == NULL || xmlXPathNodeSetIsEmpty(obj->nodesetval)) {
      xmlXPathFreeObject(obj);
      return NULL;
    }

    xmlNode* node = obj->nodesetval->nodeTab[0];
    if (node->type != XML_ATTRIBUTE_NODE) {
      xmlXPathFreeObject(obj);
      return NULL;
    }

    xmlChar* content = xmlNodeListGetString(doc, node->children, 1);
    xmlXPathFreeObject(obj);
    return content;
  } else {
    return NULL;
  }
}


int saml_doc_attrs(xmlDoc* doc, saml_attr_t** attrs, size_t* attrs_len) {
  xmlXPathObject* obj = eval_xpath(doc, XPATH_ATTRIBUTES);
  if (obj == NULL) {
    return -1;
  }

  if (xmlXPathNodeSetIsEmpty(obj->nodesetval)) {
    xmlXPathFreeObject(obj);
    *attrs_len = 0;
    *attrs = NULL;
    return 0;
  }

  *attrs_len = obj->nodesetval->nodeNr;
  *attrs = malloc(*attrs_len * sizeof(saml_attr_t));

  saml_attr_t* attr;
  xmlNode *node, *child;
  for (int i = 0; i < obj->nodesetval->nodeNr; i++) {
    attr = *attrs + i;
    node = obj->nodesetval->nodeTab[i];
    attr->name = xmlGetProp(node, (xmlChar*)"Name");
    if (attr->name == NULL) {
      continue;
    }

    attr->num_values = xmlChildElementCount(node);

    switch (attr->num_values) {
      case 0:
        attr->values = NULL;
        break;
      case 1:
        child = xmlFirstElementChild(node);
        if (child == NULL) {
          // this should never happen based on element count
          attr->values = NULL;
        } else {
          attr->values = malloc(attr->num_values * sizeof(xmlChar*));
          attr->values[0] = xmlNodeListGetString(doc, child->children, 1);
        }
        break;
      default: // Create a list of the values
        attr->values = malloc(attr->num_values * sizeof(xmlChar*));
        child = xmlFirstElementChild(node);
        for (int j = 0; j < attr->num_values; j++) {
          attr->values[j] = child->type == XML_ELEMENT_NODE ? xmlNodeListGetString(doc, child->children, 1) : NULL;
          child = xmlNextElementSibling(child);
        }
        break;
    }
  }
  xmlXPathFreeObject(obj);
  return 0;
}


void saml_attrs_free(saml_attr_t* attrs, size_t attrs_len) {
  for (int i = 0; i < attrs_len; i++) {
    if (attrs[i].name != NULL) {
      xmlFree(attrs[i].name);
      for (int j = 0; j < attrs[i].num_values; j++) {
        if (attrs[i].values[j] != NULL) {
          xmlFree(attrs[i].values[j]);
        }
      }
    }
  }
  free(attrs);
}


// An absent attribute and one whose value could not be copied both come back
// NULL from xmlGetNoNsProp, and every caller here reads NULL as "the IdP said
// nothing". For a bound or an endpoint that is a constraint quietly dropped, so
// tell the two apart and let the read fail rather than the check.
static int read_attr(xmlNode* node, const char* name, xmlChar** out) {
  *out = xmlGetNoNsProp(node, (const xmlChar*)name);
  if (*out == NULL && xmlHasNsProp(node, (const xmlChar*)name, NULL) != NULL) {
    return -1;
  }
  return 0;
}


// A direct child element of node named name in the assertion namespace.
static int is_assertion_el(xmlNode* node, const char* name) {
  return node->type == XML_ELEMENT_NODE &&
    xmlStrEqual(node->name, (const xmlChar*)name) == 1 &&
    node->ns != NULL &&
    xmlStrEqual(node->ns->href, (const xmlChar*)SAML_XMLNS_ASSERTION) == 1;
}


static xmlNode* assertion_child(xmlNode* node, const char* name) {
  for (xmlNode* child = node->children; child != NULL; child = child->next) {
    if (is_assertion_el(child, name)) {
      return child;
    }
  }
  return NULL;
}


static size_t count_assertion_el(xmlNode* parent, const char* name) {
  size_t n = 0;
  for (xmlNode* child = parent->children; child != NULL; child = child->next) {
    if (is_assertion_el(child, name)) {
      n++;
    }
  }
  return n;
}


// Conditions this SP can actually satisfy. SAML Core 2.5.1 makes an assertion
// carrying any other one Indeterminate rather than valid, so everything else is
// reported for the caller to refuse.
//
// ProxyRestriction is here because it binds an IdP issuing on behalf of another
// IdP and asks nothing of the SP consuming the assertion. OneTimeUse is not,
// because honouring it means remembering which assertions have been spent, and
// Core 2.5.1.5 tells a party that cannot keep that record to treat the
// assertion as invalid.
static int is_known_condition(xmlNode* node) {
  return is_assertion_el(node, "AudienceRestriction") ||
    is_assertion_el(node, "ProxyRestriction");
}


// Each AudienceRestriction is a separate restriction and the assertion applies
// only where all of them do, so they are kept apart rather than flattened.
static int read_audience_restrictions(xmlDoc* doc, xmlNode* conditions, saml_assertion_t* a) {
  size_t count = count_assertion_el(conditions, "AudienceRestriction");
  if (count == 0) {
    return 0;
  }

  a->audience_restrictions = calloc(count, sizeof(saml_audience_restriction_t));
  if (a->audience_restrictions == NULL) {
    return -1;
  }
  a->audience_restrictions_len = count;

  size_t i = 0;
  for (xmlNode* node = conditions->children; node != NULL; node = node->next) {
    if (!is_assertion_el(node, "AudienceRestriction")) {
      continue;
    }

    saml_audience_restriction_t* restriction = a->audience_restrictions + i++;
    size_t audiences = count_assertion_el(node, "Audience");
    if (audiences == 0) {
      continue;
    }

    restriction->audiences = calloc(audiences, sizeof(xmlChar*));
    if (restriction->audiences == NULL) {
      return -1;
    }
    restriction->audiences_len = audiences;

    size_t j = 0;
    for (xmlNode* child = node->children; child != NULL; child = child->next) {
      if (is_assertion_el(child, "Audience")) {
        restriction->audiences[j++] = xmlNodeListGetString(doc, child->children, 1);
      }
    }
  }
  return 0;
}


static int read_subject_confirmations(xmlNode* subject, saml_assertion_t* a) {
  size_t count = count_assertion_el(subject, "SubjectConfirmation");
  if (count == 0) {
    return 0;
  }

  a->confirmations = calloc(count, sizeof(saml_subject_confirmation_t));
  if (a->confirmations == NULL) {
    return -1;
  }
  a->confirmations_len = count;

  size_t i = 0;
  for (xmlNode* node = subject->children; node != NULL; node = node->next) {
    if (!is_assertion_el(node, "SubjectConfirmation")) {
      continue;
    }

    saml_subject_confirmation_t* confirmation = a->confirmations + i++;
    if (read_attr(node, "Method", &confirmation->method) < 0) {
      return -1;
    }

    xmlNode* data = assertion_child(node, "SubjectConfirmationData");
    if (data == NULL) {
      continue;
    }
    if (read_attr(data, "Recipient", &confirmation->recipient) < 0 ||
        read_attr(data, "NotBefore", &confirmation->not_before) < 0 ||
        read_attr(data, "NotOnOrAfter", &confirmation->not_on_or_after) < 0 ||
        read_attr(data, "InResponseTo", &confirmation->in_response_to) < 0) {
      return -1;
    }
  }
  return 0;
}


static int read_assertion(xmlDoc* doc, xmlNode* node, saml_assertion_t* a) {
  if (read_attr(node, "ID", &a->id) < 0) {
    return -1;
  }

  // An ID is unique only within the IdP that minted it, so the caller keeps the
  // two together. Absent and empty read alike here, as they do for doc_issuers.
  a->issuer = issuer_of(doc, node);

  xmlNode* conditions = assertion_child(node, "Conditions");
  if (conditions != NULL) {
    a->has_conditions = 1;
    if (read_attr(conditions, "NotBefore", &a->not_before) < 0 ||
        read_attr(conditions, "NotOnOrAfter", &a->not_on_or_after) < 0) {
      return -1;
    }

    for (xmlNode* child = conditions->children; child != NULL; child = child->next) {
      if (child->type == XML_ELEMENT_NODE && !is_known_condition(child)) {
        // the caller refuses the assertion on this name, so losing it would
        // let the condition through rather than fail the read
        a->unknown_condition = xmlStrdup(child->name);
        if (a->unknown_condition == NULL) {
          return -1;
        }
        break;
      }
    }

    if (read_audience_restrictions(doc, conditions, a) < 0) {
      return -1;
    }
  }

  xmlNode* subject = assertion_child(node, "Subject");
  if (subject != NULL && read_subject_confirmations(subject, a) < 0) {
    return -1;
  }
  return 0;
}


// The constraints every top-level assertion of a Response attaches to itself:
// the validity window, the audiences it is restricted to, and the subject
// confirmations that say where and until when it may be presented. They are
// reported per assertion because they belong to one assertion rather than to
// the document, and a reader consumes several. Messages carrying no assertion
// report none.
int saml_doc_assertions(xmlDoc* doc, saml_assertion_t** assertions, size_t* assertions_len) {
  *assertions = NULL;
  *assertions_len = 0;

  xmlNode* root = xmlDocGetRootElement(doc);
  if (root == NULL || xmlStrEqual(root->name, (const xmlChar*)"Response") != 1) {
    return 0;
  }

  size_t count = 0;
  for (xmlNode* child = root->children; child != NULL; child = child->next) {
    if (is_saml_assertion(child)) {
      count++;
    }
  }
  if (count == 0) {
    return 0;
  }

  saml_assertion_t* list = calloc(count, sizeof(saml_assertion_t));
  if (list == NULL) {
    return -1;
  }

  size_t i = 0;
  for (xmlNode* child = root->children; child != NULL; child = child->next) {
    if (!is_saml_assertion(child)) {
      continue;
    }
    if (read_assertion(doc, child, list + i++) < 0) {
      saml_assertions_free(list, count);
      return -1;
    }
  }

  *assertions = list;
  *assertions_len = count;
  return 0;
}


// The Destination of the root message, through an out parameter so that a value
// which could not be read is distinguishable from one that is absent. The caller
// skips the check on absent, which is the wrong answer for the other.
int saml_doc_destination(xmlDoc* doc, xmlChar** destination) {
  *destination = NULL;

  xmlNode* root = xmlDocGetRootElement(doc);
  if (root == NULL) {
    return 0;
  }
  return read_attr(root, "Destination", destination);
}


// What the root message answers, or NULL when it answers nothing. Reported
// separately from a read that failed, for the same reason as Destination.
int saml_doc_in_response_to(xmlDoc* doc, xmlChar** in_response_to) {
  *in_response_to = NULL;

  xmlNode* root = xmlDocGetRootElement(doc);
  if (root == NULL) {
    return 0;
  }
  return read_attr(root, "InResponseTo", in_response_to);
}


void saml_assertions_free(saml_assertion_t* assertions, size_t assertions_len) {
  for (size_t i = 0; i < assertions_len; i++) {
    saml_assertion_t* a = assertions + i;
    xmlFree(a->id);
    xmlFree(a->issuer);
    xmlFree(a->not_before);
    xmlFree(a->not_on_or_after);
    xmlFree(a->unknown_condition);

    for (size_t j = 0; j < a->audience_restrictions_len; j++) {
      saml_audience_restriction_t* restriction = a->audience_restrictions + j;
      for (size_t k = 0; k < restriction->audiences_len; k++) {
        xmlFree(restriction->audiences[k]);
      }
      free(restriction->audiences);
    }
    free(a->audience_restrictions);

    for (size_t j = 0; j < a->confirmations_len; j++) {
      saml_subject_confirmation_t* confirmation = a->confirmations + j;
      xmlFree(confirmation->method);
      xmlFree(confirmation->recipient);
      xmlFree(confirmation->not_before);
      xmlFree(confirmation->not_on_or_after);
      xmlFree(confirmation->in_response_to);
    }
    free(a->confirmations);
  }
  free(assertions);
}
