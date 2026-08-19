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
