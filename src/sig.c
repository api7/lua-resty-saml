xmlSecTransformCtx* saml_sign_binary(xmlSecKey* key, xmlSecTransformId transform_id, unsigned char* data, size_t data_len) {
  xmlSecTransformCtx* ctx = xmlSecTransformCtxCreate();
  if (ctx == NULL) {
    saml_log("transform ctx create failed");
    return NULL;
  }

  if (xmlSecTransformCtxInitialize(ctx) < 0) {
    xmlSecTransformCtxDestroy(ctx);
    saml_log("transform ctx create failed");
    return NULL;
  }

  if (xmlSecPtrListAdd(&ctx->enabledTransforms, (void*)transform_id) < 0) {
    xmlSecTransformCtxDestroy(ctx);
    saml_log("transform enable failed");
    return NULL;
  }

  xmlSecTransform* transform = xmlSecTransformCtxCreateAndAppend(ctx, transform_id);
  if (transform == NULL) {
    xmlSecTransformCtxDestroy(ctx);
    saml_log("transform add to context failed");
    return NULL;
  }

  transform->operation = xmlSecTransformOperationSign;

  if (xmlSecTransformSetKey(transform, key) < 0) {
    xmlSecTransformCtxDestroy(ctx);
    saml_log("set key failed");
    return NULL;
  }

  if (xmlSecTransformCtxBinaryExecute(ctx, data, data_len) < 0) {
    xmlSecTransformCtxDestroy(ctx);
    saml_log("signature execution failed");
    return NULL;
  }

  if (ctx->status != xmlSecTransformStatusFinished) {
    xmlSecTransformCtxDestroy(ctx);
    saml_log("signature status unknown");
    return NULL;
  }

  return ctx;
}


int saml_verify_binary(xmlSecKey* cert, xmlSecTransformId transform_id, unsigned char* data, size_t data_len, unsigned char* sig, size_t sig_len) {
  xmlSecTransformCtx* ctx = xmlSecTransformCtxCreate();
  if (ctx == NULL) {
    saml_log("transform ctx create failed");
    return -1;
  }

  if (xmlSecTransformCtxInitialize(ctx) < 0) {
    xmlSecTransformCtxDestroy(ctx);
    saml_log("transform ctx create failed");
    return -1;
  }

  if (xmlSecPtrListAdd(&ctx->enabledTransforms, (void*)transform_id) < 0) {
    xmlSecTransformCtxDestroy(ctx);
    saml_log("transform enable failed");
    return -1;
  }

  xmlSecTransform* transform = xmlSecTransformCtxCreateAndAppend(ctx, transform_id);
  if (transform == NULL) {
    xmlSecTransformCtxDestroy(ctx);
    saml_log("transform add to context failed");
    return -1;
  }

  transform->operation = xmlSecTransformOperationVerify;

  if (xmlSecTransformSetKey(transform, cert) < 0) {
    xmlSecTransformCtxDestroy(ctx);
    saml_log("set key failed");
    return -1;
  }

  if (xmlSecTransformCtxBinaryExecute(ctx, data, data_len) < 0) {
    xmlSecTransformCtxDestroy(ctx);
    saml_log("binary execution failed");
    return -1;
  }

  if (ctx->status != xmlSecTransformStatusFinished) {
    xmlSecTransformCtxDestroy(ctx);
    saml_log("transform context status unknown");
    return -1;
  }

  if (xmlSecTransformVerify(transform, sig, sig_len, ctx) < 0) {
    xmlSecTransformCtxDestroy(ctx);
    saml_log("transform verify failed");
    return -1;
  }

  int status = transform->status == xmlSecTransformStatusOk ? 0 : 1;
  xmlSecTransformCtxDestroy(ctx);
  return status;
}


static void add_id(xmlDoc* doc, xmlNode* node, const xmlChar* name) {
  xmlAttr* attr = node->properties;
  while (attr != NULL) {
    if (xmlStrEqual(attr->name, name) == 1) {
      xmlChar* value = xmlNodeListGetString(doc, attr->children, 1);
      if (value != NULL) {
        xmlAddID(NULL, doc, value, attr);
      }
      return;
    }
    attr = attr->next;
  }
}


int saml_sign_doc(xmlSecKey* key, xmlSecTransformId transform_id, xmlDoc* doc, saml_doc_opts_t* opts) {
  xmlNode* root = xmlDocGetRootElement(doc);
  if (root == NULL) {
    saml_log("no root node");
    return 1;
  }

  const xmlChar uri[80] = "#\0";
  if (opts->id_attr != NULL) {
    xmlChar* id = xmlGetProp(root, opts->id_attr);
    if (id == NULL) {
      saml_log("no ID property on document root");
      return 1;
    }
    strncat((char*)uri, (char*)id, sizeof(uri) - 2);
    xmlFree(id);
    add_id(doc, root, opts->id_attr);
  }

  // <dsig:Signature/>
  xmlNode* sig = xmlSecTmplSignatureCreate(doc, xmlSecTransformExclC14NId, transform_id, NULL);
  if (sig == NULL) {
    saml_log("create signature template failed");
    return -1;
  }

  if (opts->insert_after_ns != NULL && opts->insert_after_el != NULL) {
    xmlNode* target = xmlSecFindNode(root, opts->insert_after_el, opts->insert_after_ns);
    if (target == NULL) {
      saml_log("insertion point node not found");
      return 1;
    }

    if (xmlAddNextSibling(target, sig) == NULL) {
      saml_log("adding signature node failed");
      return -1;
    }
  } else {
    xmlAddChild(root, sig);
  }

  // <dsig:Reference/>
  xmlNode* ref = xmlSecTmplSignatureAddReference(sig, xmlSecTransformSha1Id, NULL, (opts->id_attr == NULL) ? NULL : uri, NULL);
  if (ref == NULL) {
    saml_log("add reference to signature template failed");
    return -1;
  }

  if (xmlSecTmplReferenceAddTransform(ref, xmlSecTransformEnvelopedId) == NULL) {
    saml_log("add enveloped transform to reference failed");
    return -1;
  }

  if (xmlSecTmplReferenceAddTransform(ref, xmlSecTransformExclC14NId) == NULL) {
    saml_log("add c14n transform to reference failed");
    return -1;
  }

  // <dsig:KeyInfo/>
  xmlNode* key_info = xmlSecTmplSignatureEnsureKeyInfo(sig, NULL);
  if (key_info == NULL) {
    saml_log("add key info to sign node failed");
    return -1;
  }
 
  // <dsig:X509Data/>
  xmlNode* x509_data = xmlSecTmplKeyInfoAddX509Data(key_info);
  if (x509_data == NULL) {
    saml_log("add x509 data to node failed");
    return -1;
  }

  if (xmlSecTmplX509DataAddCertificate(x509_data) == NULL) {
    saml_log("add x509 cert to node failed");
    return -1;
  }

  xmlSecDSigCtx* ctx = xmlSecDSigCtxCreate(NULL);
  if (ctx == NULL) {
    saml_log("create signature context failed");
    return -1;
  }

  ctx->signKey = key;
  int res = xmlSecDSigCtxSign(ctx, sig);
  ctx->signKey = NULL; // The signKey is lua userdata, so xmlsec should not manage it

  if (res < 0) {
    xmlSecDSigCtxDestroy(ctx);
    saml_log("sign failed");
    return -1;
  }

  int status = ctx->status == xmlSecDSigStatusSucceeded ? 0 : -1;
  xmlSecDSigCtxDestroy(ctx);
  return status;
}


int saml_verify_doc(xmlSecKeysMngr* mngr, xmlDoc* doc, saml_doc_opts_t* opts) {
  xmlNode* root = xmlDocGetRootElement(doc);
  if (root == NULL) {
    return 1;
  }

  if (opts->id_attr != NULL) {
    add_id(doc, root, opts->id_attr);
  }

  xmlNode* sig = xmlSecFindNode(root, xmlSecNodeSignature, xmlSecDSigNs);
  if (sig == NULL) {
    return 1;
  }

  xmlSecDSigCtx* ctx = xmlSecDSigCtxCreate(mngr);
  if (ctx == NULL) {
    xmlSecDSigCtxDestroy(ctx);
    saml_log("create signature context failed");
    return -1;
  }

  //ctx->enabledReferenceUris = xmlSecTransformUriTypeNone & xmlSecTransformUriTypeEmpty & xmlSecTransformUriTypeSameDocument;
  ctx->enabledReferenceUris = 0x0003;
  if (xmlSecDSigCtxVerify(ctx, sig) < 0) {
    xmlSecDSigCtxDestroy(ctx);
    saml_log("signature verify failed");
    return -1;
  }

  int status = ctx->status == xmlSecDSigStatusSucceeded ? 0 : 1;
  xmlSecDSigCtxDestroy(ctx);
  return status;
}


// Find the element carrying ID=id. Schema validation rejects duplicate xs:ID
// values, so within a validated document this resolves the same element the
// signature was verified against.
static xmlNode* find_by_id(xmlNode* node, const xmlChar* id) {
  for (; node != NULL; node = node->next) {
    if (node->type != XML_ELEMENT_NODE) {
      continue;
    }
    xmlChar* value = xmlGetProp(node, (const xmlChar*)"ID");
    int hit = value != NULL && xmlStrEqual(value, id) == 1;
    if (value != NULL) {
      xmlFree(value);
    }
    if (hit) {
      return node;
    }
    xmlNode* child = find_by_id(node->children, id);
    if (child != NULL) {
      return child;
    }
  }
  return NULL;
}


// The element the verified signature protects, resolved from its Reference URI.
// Reference URIs are restricted to same-document ("#id") or empty (whole
// document) forms during verification, so no other shapes are expected here.
static xmlNode* signed_reference_target(xmlDoc* doc, xmlNode* sig) {
  xmlNode* ref = xmlSecFindNode(sig, xmlSecNodeReference, xmlSecDSigNs);
  if (ref == NULL) {
    return NULL;
  }
  xmlChar* uri = xmlGetProp(ref, (const xmlChar*)"URI");
  xmlNode* target = NULL;
  if (uri == NULL || uri[0] == '\0') {
    target = xmlDocGetRootElement(doc);
  } else if (uri[0] == '#') {
    xmlAttr* id_attr = xmlGetID(doc, uri + 1);
    if (id_attr != NULL) {
      target = id_attr->parent;
    } else {
      target = find_by_id(xmlDocGetRootElement(doc), uri + 1);
    }
  }
  if (uri != NULL) {
    xmlFree(uri);
  }
  return target;
}


// saml_verify_doc validates the first Signature in the document but does not
// confirm that its Reference covers the assertion identity is later read from.
// Identity comes from an Assertion that is a direct child of the Response, and
// attributes are read across all such assertions, so the verified signature
// must cover either the whole Response or that single Assertion. Only
// successful responses are checked; others carry no identity and may hold no
// assertion.
int saml_verified_identity_is_signed(xmlDoc* doc) {
  xmlNode* root = xmlDocGetRootElement(doc);
  if (root == NULL) {
    return 0;
  }
  if (xmlStrEqual(root->name, (const xmlChar*)"Response") != 1) {
    return 1;
  }

  xmlChar* status = saml_doc_status_code(doc);
  int success = status != NULL && xmlStrEqual(status, (const xmlChar*)SAML_STATUS_SUCCESS) == 1;
  if (status != NULL) {
    xmlFree(status);
  }
  if (!success) {
    return 1;
  }

  xmlNode* sig = xmlSecFindNode(root, xmlSecNodeSignature, xmlSecDSigNs);
  if (sig == NULL) {
    return 0;
  }
  xmlNode* target = signed_reference_target(doc, sig);
  if (target == NULL) {
    return 0;
  }

  // Identity and attributes are read with document-wide queries, so the whole
  // document must contain exactly one Assertion, it must be a direct child of
  // this Response, and the verified signature must cover either the whole
  // Response or that assertion. This rejects any extra assertion nested
  // elsewhere (for example a Response placed under Extensions or Advice) that a
  // document-wide reader could otherwise pick up.
  xmlXPathContext* ctx = xmlXPathNewContext(doc);
  if (ctx == NULL) {
    return 0;
  }
  if (xmlXPathRegisterNs(ctx, (const xmlChar*)"saml", (const xmlChar*)SAML_XMLNS_ASSERTION) < 0) {
    xmlXPathFreeContext(ctx);
    return 0;
  }

  xmlXPathObject* obj = xmlXPathEvalExpression((const xmlChar*)"//saml:Assertion", ctx);
  int safe = 0;
  if (obj != NULL && !xmlXPathNodeSetIsEmpty(obj->nodesetval) && obj->nodesetval->nodeNr == 1) {
    xmlNode* assertion = obj->nodesetval->nodeTab[0];
    safe = assertion->parent == root && (target == root || target == assertion);
  }
  if (obj != NULL) {
    xmlXPathFreeObject(obj);
  }
  xmlXPathFreeContext(ctx);
  return safe;
}
