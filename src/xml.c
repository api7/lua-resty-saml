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


xmlChar* saml_doc_issuer(xmlDoc* doc) {
  xmlNode* node = xmlDocGetRootElement(doc);
  if (node == NULL) {
    return NULL;
  }

  node = node->children;
  while (node != NULL) {
    if (xmlStrEqual(node->name, (xmlChar*)"Issuer") == 1) {
      return xmlNodeListGetString(doc, node->children, 1);
    }
    node = node->next;
  }
  return NULL;
}


xmlChar* saml_doc_name_id(xmlDoc* doc) {
  xmlNode* node = xmlDocGetRootElement(doc);
  if (node == NULL) {
    return NULL;
  }

  if (xmlStrEqual(node->name, (xmlChar*)"LogoutRequest") == 1) {
    node = xmlSecFindNode(node, (xmlChar*)"NameID", (xmlChar*)SAML_XMLNS_ASSERTION);
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


// The direct child of node named name in the protocol namespace, or NULL.
static xmlNode* protocol_child(xmlNode* node, const xmlChar* name) {
  for (xmlNode* child = node->children; child != NULL; child = child->next) {
    if (child->type == XML_ELEMENT_NODE &&
        xmlStrEqual(child->name, name) == 1 &&
        child->ns != NULL &&
        xmlStrEqual(child->ns->href, (const xmlChar*)SAML_XMLNS_PROTOCOL) == 1) {
      return child;
    }
  }
  return NULL;
}


xmlChar* saml_doc_status_code(xmlDoc* doc) {
  // Read the top-level message's status directly, not a document-wide match:
  // a nested Response (for example inside saml:Advice) can precede the root
  // Status in document order and must not be mistaken for it.
  xmlNode* root = xmlDocGetRootElement(doc);
  if (root == NULL) {
    return NULL;
  }
  xmlNode* status = protocol_child(root, (const xmlChar*)"Status");
  if (status == NULL) {
    return NULL;
  }
  xmlNode* code = protocol_child(status, (const xmlChar*)"StatusCode");
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
    node = xmlSecFindNode(node, (xmlChar*)"SessionIndex", (xmlChar*)SAML_XMLNS_PROTOCOL);
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


// Defined in sig.c, which saml.c includes after this file.
static int is_saml_assertion(xmlNode* node);


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


// Conditions this reader can hand the caller enough to weigh. SAML Core 2.5.1
// makes an assertion carrying any other condition Indeterminate rather than
// valid, so anything else is reported as unrecognised for the caller to refuse.
static int is_known_condition(xmlNode* node) {
  return is_assertion_el(node, "AudienceRestriction") ||
    is_assertion_el(node, "OneTimeUse") ||
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
    confirmation->method = xmlGetNoNsProp(node, (const xmlChar*)"Method");

    xmlNode* data = assertion_child(node, "SubjectConfirmationData");
    if (data == NULL) {
      continue;
    }
    confirmation->recipient = xmlGetNoNsProp(data, (const xmlChar*)"Recipient");
    confirmation->not_before = xmlGetNoNsProp(data, (const xmlChar*)"NotBefore");
    confirmation->not_on_or_after = xmlGetNoNsProp(data, (const xmlChar*)"NotOnOrAfter");
    confirmation->in_response_to = xmlGetNoNsProp(data, (const xmlChar*)"InResponseTo");
  }
  return 0;
}


static int read_assertion(xmlDoc* doc, xmlNode* node, saml_assertion_t* a) {
  a->id = xmlGetNoNsProp(node, (const xmlChar*)"ID");

  xmlNode* conditions = assertion_child(node, "Conditions");
  if (conditions != NULL) {
    a->has_conditions = 1;
    a->not_before = xmlGetNoNsProp(conditions, (const xmlChar*)"NotBefore");
    a->not_on_or_after = xmlGetNoNsProp(conditions, (const xmlChar*)"NotOnOrAfter");

    for (xmlNode* child = conditions->children; child != NULL; child = child->next) {
      if (child->type == XML_ELEMENT_NODE && !is_known_condition(child)) {
        a->unknown_condition = xmlStrdup(child->name);
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


void saml_assertions_free(saml_assertion_t* assertions, size_t assertions_len) {
  for (size_t i = 0; i < assertions_len; i++) {
    saml_assertion_t* a = assertions + i;
    xmlFree(a->id);
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
