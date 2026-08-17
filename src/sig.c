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


// The ID a same-document fragment names, or NULL if it names something else.
// xmlsec accepts the XPointer spelling of a same-document reference as well as
// the barename SAML prescribes, so reduce xpointer(id('x')) to x. Writes into
// fragment and returns a pointer inside it.
static xmlChar* fragment_id(xmlChar* fragment) {
  static const char PREFIX[] = "xpointer(id(";
  const int prefix_len = (int)sizeof(PREFIX) - 1;

  if (xmlStrncmp(fragment, (const xmlChar*)PREFIX, prefix_len) != 0) {
    return fragment;
  }

  xmlChar* id = fragment + prefix_len;
  xmlChar quote = id[0];
  if (quote != '\'' && quote != '"') {
    return NULL;
  }
  id++;

  xmlChar* end = (xmlChar*)xmlStrchr(id, quote);
  if (end == NULL || xmlStrEqual(end + 1, (const xmlChar*)"))") != 1) {
    return NULL;
  }
  *end = '\0';
  return id;
}


// The element one Reference protects. Verification restricts Reference URIs to
// same-document ("#...") or whole-document (empty) forms, so no other shape is
// expected. A fragment libxml2 cannot resolve is treated as covering nothing:
// verification just succeeded through the same ID table, so a miss here means
// the safe reading is no coverage.
static xmlNode* reference_target(xmlDoc* doc, xmlNode* ref) {
  xmlChar* uri = xmlGetProp(ref, (const xmlChar*)"URI");
  if (uri == NULL || uri[0] == '\0') {
    if (uri != NULL) {
      xmlFree(uri);
    }
    return xmlDocGetRootElement(doc);
  }

  xmlNode* target = NULL;
  if (uri[0] == '#') {
    if (xmlStrEqual(uri + 1, (const xmlChar*)"xpointer(/)") == 1) {
      target = xmlDocGetRootElement(doc);
    } else {
      xmlChar* id = fragment_id(uri + 1);
      xmlAttr* id_attr = id == NULL ? NULL : xmlGetID(doc, id);
      if (id_attr != NULL) {
        target = id_attr->parent;
      }
    }
  }
  xmlFree(uri);
  return target;
}


// Whether the verified signature covers node. One SignedInfo can carry a
// Reference per assertion and xmlsec verifies every one of them, so consider
// them all. References outside SignedInfo (in a Manifest, say) are not
// themselves verified, so only its direct children count.
static int signature_covers(xmlDoc* doc, xmlNode* sig, xmlNode* node) {
  xmlNode* info = xmlSecFindNode(sig, xmlSecNodeSignedInfo, xmlSecDSigNs);
  if (info == NULL) {
    return 0;
  }
  for (xmlNode* ref = info->children; ref != NULL; ref = ref->next) {
    if (ref->type != XML_ELEMENT_NODE ||
        xmlStrEqual(ref->name, xmlSecNodeReference) != 1 ||
        ref->ns == NULL ||
        xmlStrEqual(ref->ns->href, xmlSecDSigNs) != 1) {
      continue;
    }
    if (reference_target(doc, ref) == node) {
      return 1;
    }
  }
  return 0;
}


static int is_saml_assertion(xmlNode* node) {
  return node->type == XML_ELEMENT_NODE &&
    xmlStrEqual(node->name, (const xmlChar*)"Assertion") == 1 &&
    node->ns != NULL &&
    xmlStrEqual(node->ns->href, (const xmlChar*)SAML_XMLNS_ASSERTION) == 1;
}


// Identity is read from /samlp:Response/saml:Assertion, i.e. only from an
// assertion that is a direct child of the verified root message. saml_verify_doc
// checks one Signature but not that it covers the assertion a reader will pick,
// so remove every top-level assertion that signature leaves out. A signature
// over the whole message covers all of them. The removed nodes are siblings, so
// freeing one never dangles another.
static void confine_identity_to_signature(xmlDoc* doc) {
  xmlNode* root = xmlDocGetRootElement(doc);
  if (root == NULL) {
    return;
  }
  xmlNode* sig = xmlSecFindNode(root, xmlSecNodeSignature, xmlSecDSigNs);
  if (sig != NULL && signature_covers(doc, sig, root)) {
    return;
  }
  xmlNode* child = root->children;
  while (child != NULL) {
    xmlNode* next = child->next;
    if (is_saml_assertion(child) && (sig == NULL || !signature_covers(doc, sig, child))) {
      xmlUnlinkNode(child);
      xmlFreeNode(child);
    }
    child = next;
  }
}
