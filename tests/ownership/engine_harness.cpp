/*
 * Synthetic 4D engine boundary for ownership regressions.
 *
 * Compiles the real plugin entry point (4DPlugin-Timestamp.cpp, included
 * below) and links the real support/4DPlugin-JSON.cpp, the SDK classes that
 * the Xcode/vcxproj builds use (C_BLOB, C_LONGINT, C_TEXT), the unmodified
 * 4DPluginAPI.c and the bundled static OpenSSL. Only gCall4D is replaced.
 * Every engine resource (Unistrings, pictures, objects/collections, handles)
 * is a real heap block tracked in a live set, so leaks are detected exactly
 * and a dispose of something the engine no longer owns (double free) is
 * reported by name instead of being freed a second time.
 *
 * No timestamp authority is contacted and no network I/O happens: the plugin
 * only uses memory BIOs, the inputs are synthetic, and connect()/
 * getaddrinfo() abort the harness if anything ever reaches them. CA paths in
 * the options point nowhere and are never opened, because verification of a
 * malformed or rejected synthetic response fails first or uses an empty store.
 *
 * Engine semantics modelled (per the SDK contract):
 *  - PA_CreateVariable(eVK_Unistring/eVK_Picture) allocates an empty value.
 *  - PA_GetStringVariable returns a view borrowed from the variable.
 *  - PA_SetObjectProperty deep-copies strings and pictures and retains
 *    objects/collections; the caller still owns its variable.
 *  - PA_GetObjectProperty returns an owned copy (or a retained object/
 *    collection) that must be cleared; on error the result is left
 *    uninitialised (poisoned here) and must be neither read nor cleared.
 *  - PA_ExecuteCommandByID returns an owned result.
 */

/* Resolved through -I <source-root>, so the same harness tests baseline and fixed trees. */
#include "4DPlugin-Timestamp.cpp"

#include "PrivateTypes.h"
#include "EntryPoints.h"

#include <netdb.h>
#include <sys/socket.h>

#include <map>
#include <set>
#include <string>
#include <vector>

/* Network tripwires: statically linked OpenSSL binds to these definitions. */
extern "C" int connect(int, const struct sockaddr *, socklen_t) {
    fprintf(stderr, "HARNESS ERROR: network connect attempted\n"); abort();
}
extern "C" int getaddrinfo(const char *, const char *, const struct addrinfo *, struct addrinfo **) {
    fprintf(stderr, "HARNESS ERROR: name resolution attempted\n"); abort();
}

extern "C" Call4DProcPtr gCall4D;

namespace {

typedef std::basic_string<PA_Unichar> u16;

struct Obj {
    int rc;
    bool coll;
    std::map<u16, PA_Variable> props;
    std::vector<PA_Variable> items;
};

/* data first: the SDK dereferences array handles directly (*(T**)handle). */
struct Handle { char *data; size_t size; };

std::set<void *> g_strings;
std::set<void *> g_pictures;
std::set<Obj *> g_objects;
std::set<void *> g_handles;
std::vector<std::string> g_violations;

/* PA_GetObjectProperty for this key fails: eb.fError is set and the result
   is left uninitialised. The poison is readable (tests fail by assertion,
   not by crashing) but never engine-owned, so clearing it is counted. */
std::string g_fail_key;
/* JSON Stringify (1217) fails the same way. */
bool g_fail_stringify = false;
const char kPoisonMark = 0x5A;
int g_poison_clears = 0;
PA_Unichar kPoisonBuf[] = { 'B', 'A', 'D', '!', 0 };
PA_Unichar *const kPoison = kPoisonBuf;

PA_Variable undefined_var();

void poison(PA_Variable *out) {
    *out = undefined_var();
    out->fFiller = kPoisonMark;
    out->fType = eVK_Unistring;
    out->uValue.fString.fString = kPoison;
    out->uValue.fString.fLength = 4;
}

void violation(const std::string &what) {
    fprintf(stderr, "  ENGINE CONTRACT: %s\n", what.c_str());
    g_violations.push_back(what);
}

[[noreturn]] void die(const char *msg) {
    fprintf(stderr, "HARNESS ERROR: %s\n", msg);
    fflush(stderr);
    abort();
}

std::string narrow(const u16 &s) { std::string r; for(PA_Unichar c : s) r.push_back((char)c); return r; }
u16 widen(const std::string &s) { u16 r; for(char c : s) r.push_back((PA_Unichar)(unsigned char)c); return r; }

PA_Unistring new_string(const PA_Unichar *src, size_t len) {
    PA_Unichar *buf = (PA_Unichar *)malloc((len + 1) * sizeof(PA_Unichar));
    if(len) memcpy(buf, src, len * sizeof(PA_Unichar));
    buf[len] = 0;
    g_strings.insert(buf);
    PA_Unistring s;
    s.fLength = (PA_long32)len;
    s.fString = buf;
    s.fReserved1 = 0;
    s.fReserved2 = 0;
    return s;
}

void free_string(PA_Unistring *s) {
    if(!s->fString) return;
    if(s->fString == kPoison) {
        g_poison_clears++;
        fprintf(stderr, "  cleared the uninitialised result of a failed engine call\n");
    } else if(!g_strings.erase(s->fString)) {
        violation("double_dispose_string");
    } else {
        free(s->fString);
    }
    s->fString = 0;
    s->fLength = 0;
}

void *new_picture() {
    void *p = malloc(16);
    g_pictures.insert(p);
    return p;
}

void free_picture(void *p) {
    if(!p) return;
    if(!g_pictures.erase(p)) { violation("double_dispose_picture"); return; }
    free(p);
}

Handle *new_handle(size_t size) {
    Handle *h = (Handle *)malloc(sizeof(Handle));
    h->size = size;
    h->data = (char *)calloc(1, size ? size : 1);
    g_handles.insert(h);
    return h;
}

void free_handle(Handle *h) {
    if(!h) return;
    if(!g_handles.erase(h)) { violation("double_dispose_handle"); return; }
    free(h->data);
    free(h);
}

Handle *live_handle(void *p) {
    if(!g_handles.count(p)) die("used an unknown handle");
    return (Handle *)p;
}

void release_object(Obj *o);

void clear_var(PA_Variable *v) {
    if(v->fFiller == kPoisonMark) {
        g_poison_clears++;
        fprintf(stderr, "  cleared the uninitialised result of a failed engine call\n");
        v->fType = eVK_Undefined;
        v->fFiller = 0;
        return;
    }
    switch(v->fType) {
        case eVK_Unistring: free_string(&v->uValue.fString); break;
        case eVK_Picture: free_picture(v->uValue.fPicture); break;
        case eVK_Blob: free_handle((Handle *)v->uValue.fBlob.fHandle); break;
        case eVK_Object: if(v->uValue.fObject) release_object((Obj *)v->uValue.fObject); break;
        case eVK_Collection: if(v->uValue.fCollection) release_object((Obj *)v->uValue.fCollection); break;
        case eVK_ArrayUnicode: {
            Handle *h = live_handle(v->uValue.fArray.fData);
            PA_Unistring *s = (PA_Unistring *)h->data;
            for(PA_long32 i = 0; i <= v->uValue.fArray.fNbElements; i++) free_string(&s[i]);
            free_handle(h);
            break;
        }
        default: break;
    }
    v->fType = eVK_Undefined;
}

Obj *live(void *p) {
    if(!g_objects.count((Obj *)p)) die("used a dead object/collection");
    return (Obj *)p;
}

PA_Variable undefined_var() { PA_Variable v; memset(&v, 0, sizeof(v)); v.fType = eVK_Undefined; return v; }

PA_Variable copy_var(const PA_Variable &src) {
    PA_Variable dst = src;
    switch(src.fType) {
        case eVK_Unistring:
            dst.uValue.fString = new_string(src.uValue.fString.fString, src.uValue.fString.fLength);
            break;
        case eVK_Picture:
            if(!g_pictures.count(PA_Picture(src.uValue.fPicture))) die("stored a dead picture");
            dst.uValue.fPicture = new_picture();
            break;
        case eVK_Object:
            if(src.uValue.fObject) live(src.uValue.fObject)->rc++;
            break;
        case eVK_Collection:
            if(src.uValue.fCollection) live(src.uValue.fCollection)->rc++;
            break;
        default: break;
    }
    return dst;
}

Obj *new_object(bool coll = false) {
    Obj *o = new Obj();
    o->rc = 1;
    o->coll = coll;
    g_objects.insert(o);
    return o;
}

void release_object(Obj *o) {
    if(!g_objects.count(o)) { violation("double_release_object"); return; }
    if(--o->rc == 0) {
        for(auto &kv : o->props) clear_var(&kv.second);
        for(auto &v : o->items) clear_var(&v);
        g_objects.erase(o);
        delete o;
    }
}

u16 key_of(const PA_Unistring &k) { return u16(k.fString, k.fLength); }

PA_Variable object_result(Obj *o) {
    PA_Variable v = undefined_var();
    v.fType = o->coll ? eVK_Collection : eVK_Object;
    if(o->coll) v.uValue.fCollection = (PA_CollectionRef)o; else v.uValue.fObject = (PA_ObjectRef)o;
    return v;
}

void execute_command(EngineBlock *eb) {
    PA_Variable **params = (PA_Variable **)eb->fPtr1;
    PA_Variable *ret = (PA_Variable *)eb->fPtr2;
    switch(eb->fParam1) {
        case 1225: { /* OB Copy */
            Obj *src = live(params[0]->uValue.fObject);
            Obj *dst = new_object(false);
            for(auto &kv : src->props) dst->props[kv.first] = copy_var(kv.second);
            *ret = object_result(dst);
            break;
        }
        case 1217: { /* JSON Stringify */
            live(params[0]->uValue.fObject);
            if(g_fail_stringify) { poison(ret); eb->fError = -1; break; }
            u16 json = widen("{}");
            ret->fType = eVK_Unistring;
            ret->uValue.fString = new_string(json.c_str(), json.size());
            break;
        }
        case 1231: { /* OB Is defined */
            Obj *o = live(params[0]->uValue.fObject);
            ret->fType = eVK_Boolean;
            ret->uValue.fBoolean = o->props.count(key_of(params[1]->uValue.fString)) ? 1 : 0;
            break;
        }
        case 1471: *ret = object_result(new_object(false)); break; /* New Object */
        case 1472: *ret = object_result(new_object(true)); break; /* New Collection */
        default: {
            char msg[64];
            snprintf(msg, sizeof(msg), "unexpected PA_ExecuteCommandByID %d", (int)eb->fParam1);
            die(msg);
        }
    }
}

void engine(short selector, EngineBlock *eb) {
    switch(selector) {
        case EX_CREATE_UNISTRING: {
            const PA_Unichar *src = (const PA_Unichar *)eb->fHandle;
            size_t len = 0;
            while(src[len]) len++;
            eb->fUniString1 = new_string(src, len);
            break;
        }
        case EX_DISPOSE_UNISTRING:
            free_string(&eb->fUniString1);
            break;
        case EX_VARIABLE_TO_STRING: {
            PA_Variable *v = (PA_Variable *)eb->fHandle;
            if(v->fType == eVK_Unistring) eb->fUniString1 = v->uValue.fString; /* borrowed */
            break;
        }
        case EX_CREATE_PICTURE:
            eb->fPicture = new_picture();
            break;
        case EX_DISPOSE_PICTURE:
            free_picture(eb->fPicture);
            break;
        case EX_CLEAR_VARIABLE:
            clear_var((PA_Variable *)eb->fPtr1);
            break;
        case EX_GET_INFORMATION:
            eb->fParam2 = 0x00002000; /* 4D v20: PA_CreateObject uses New Object */
            break;
        case EX_SET_OBJ_VALUE: {
            Obj *o = live(eb->fPtr1);
            if(eb->fShort == eVK_Collection) die("collection set not modelled");
            PA_Variable value = copy_var(*(PA_Variable *)eb->fPtr2);
            u16 k = key_of(eb->fUniString1);
            auto it = o->props.find(k);
            if(it != o->props.end()) clear_var(&it->second);
            o->props[k] = value;
            break;
        }
        case EX_GET_OBJ_VALUE: {
            if(!eb->fPtr1) { violation("property_of_null_object"); *(PA_Variable *)eb->fPtr2 = undefined_var(); eb->fError = -1; break; }
            Obj *o = live(eb->fPtr1);
            PA_Variable *out = (PA_Variable *)eb->fPtr2;
            if(eb->fShort == eVK_Collection) die("collection get not modelled");
            u16 k = key_of(eb->fUniString1);
            if(!g_fail_key.empty() && narrow(k) == g_fail_key) {
                poison(out);
                eb->fError = -1;
                break;
            }
            auto it = o->props.find(k);
            *out = it == o->props.end() ? undefined_var() : copy_var(it->second);
            break;
        }
        case EX_EXECUTE_COMMAND_BY_ID:
            execute_command(eb);
            break;
        case EX_HANDLE_MANAGER: {
            switch(eb->fParam1) {
                case 1: eb->fHandle = (PA_Handle)new_handle((size_t)eb->fParam2); break;
                case 2: free_handle((Handle *)eb->fHandle); break;
                case 3: {
                    Handle *h = live_handle(eb->fHandle);
                    size_t n = (size_t)eb->fParam2;
                    char *d = (char *)calloc(1, n ? n : 1);
                    memcpy(d, h->data, n < h->size ? n : h->size);
                    free(h->data);
                    h->data = d;
                    h->size = n;
                    break;
                }
                case 4: eb->fParam2 = (sLONG_PTR)live_handle(eb->fHandle)->size; break;
                case 5: eb->fParam3 = (sLONG_PTR)live_handle(eb->fHandle)->data; break;
                case 6: break;
                default: die("unexpected handle manager op");
            }
            break;
        }
        default: {
            char msg[64];
            snprintf(msg, sizeof(msg), "unmodelled engine selector %d", selector);
            die(msg);
        }
    }
}

/* ---------- test helpers ---------- */

PA_Unistring U(const char *ascii) {
    u16 s = widen(ascii);
    return new_string(s.c_str(), s.size());
}

void put(Obj *o, const char *key, PA_Variable v) {
    PA_Unistring k = U(key);
    PA_SetObjectProperty((PA_ObjectRef)o, &k, v);
    PA_DisposeUnistring(&k);
}

void put_text(Obj *o, const char *key, const char *value) {
    PA_Variable v = undefined_var();
    PA_Unistring u = U(value);
    PA_SetStringVariable(&v, &u);
    put(o, key, v);
    PA_ClearVariable(&v);
}

void put_real(Obj *o, const char *key, double d) {
    PA_Variable v = undefined_var();
    PA_SetRealVariable(&v, d);
    put(o, key, v);
}

Obj *put_object(Obj *o, const char *key, bool coll) {
    Obj *c = new_object(coll);
    PA_Variable v = object_result(c);
    put(o, key, v);
    PA_ClearVariable(&v);
    return c;
}

bool check(bool ok, const char *what) {
    if(!ok) fprintf(stderr, "  check failed: %s\n", what);
    return ok;
}

bool no_leaks() {
    bool ok = true;
    for(void *p : g_strings) {
        fprintf(stderr, "  LEAK: engine string \"%s\"\n", narrow(u16((PA_Unichar *)p)).c_str());
        ok = false;
    }
    if(!g_pictures.empty()) { fprintf(stderr, "  LEAK: %zu engine picture(s)\n", g_pictures.size()); ok = false; }
    if(!g_objects.empty()) { fprintf(stderr, "  LEAK: %zu engine object(s)/collection(s)\n", g_objects.size()); ok = false; }
    if(!g_handles.empty()) { fprintf(stderr, "  LEAK: %zu engine handle(s)\n", g_handles.size()); ok = false; }
    if(g_poison_clears) { fprintf(stderr, "  %d failed result(s) cleared\n", g_poison_clears); ok = false; }
    if(!g_violations.empty()) ok = false;
    return ok;
}

/* ---------- plugin command drivers ---------- */

PA_Handle blob_handle(const std::string &bytes) {
    Handle *h = new_handle(bytes.size());
    if(bytes.size()) memcpy(h->data, bytes.data(), bytes.size());
    return (PA_Handle)h;
}

std::string take_blob(PA_Handle h) {
    if(!h) return std::string();
    Handle *hh = live_handle(h);
    std::string r(hh->data, hh->size);
    free_handle(hh);
    return r;
}

/* Calls the real `Create timestamp query` (selector 1) with a borrowed options object. */
std::string call_create_query(const std::string &data, Obj *options) {
    PA_Handle p1 = blob_handle(data);
    PA_ObjectRef p2 = (PA_ObjectRef)options;
    void *args[2] = { &p1, &p2 };
    PA_Handle result = NULL;
    PluginBlock pb;
    pb.fParameters = args;
    pb.fResult = &result;
    PluginMain(1, &pb);
    free_handle(live_handle(p1));
    return take_blob(result);
}

/* Calls the real `Verify timestamp request` (selector 2); returns the owned result object. */
Obj *call_verify(const std::string &tsr, const std::string &tsq, Obj *options) {
    PA_Handle p1 = blob_handle(tsr);
    PA_Handle p2 = blob_handle(tsq);
    PA_ObjectRef p3 = (PA_ObjectRef)options;
    void *args[3] = { &p1, &p2, &p3 };
    PA_ObjectRef result = NULL;
    PluginBlock pb;
    pb.fParameters = args;
    pb.fResult = &result;
    PluginMain(2, &pb);
    free_handle(live_handle(p1));
    free_handle(live_handle(p2));
    return result ? live(result) : NULL;
}

void init_plugin() {
    PluginBlock pb;
    pb.fParameters = NULL;
    pb.fResult = NULL;
    PluginMain(kInitPlugin, &pb);
}

TS_REQ *parse_query(const std::string &der) {
    const unsigned char *p = (const unsigned char *)der.data();
    return d2i_TS_REQ(NULL, &p, (long)der.size());
}

std::string policy_of(TS_REQ *q) {
    ASN1_OBJECT *o = TS_REQ_get_policy_id(q);
    if(!o) return std::string();
    char buf[128];
    OBJ_obj2txt(buf, sizeof(buf), o, 1);
    return buf;
}

int md_nid_of(TS_REQ *q) {
    X509_ALGOR *a = TS_MSG_IMPRINT_get_algo(TS_REQ_get_msg_imprint(q));
    return OBJ_obj2nid(a->algorithm);
}

/* A syntactically valid TS_RESP with status "rejection" (no token): parses,
   prints and fails verification without any CA material being loaded. */
std::string synthetic_rejection() {
    TS_RESP *resp = TS_RESP_new();
    TS_STATUS_INFO *si = TS_STATUS_INFO_new();
    TS_STATUS_INFO_set_status(si, TS_STATUS_REJECTION);
    TS_RESP_set_status_info(resp, si);
    TS_STATUS_INFO_free(si);
    unsigned char *der = NULL;
    int len = i2d_TS_RESP(resp, &der);
    std::string r((const char *)der, len > 0 ? len : 0);
    OPENSSL_free(der);
    TS_RESP_free(resp);
    return r;
}

std::string prop_text(Obj *o, const char *key) {
    auto it = o->props.find(widen(key));
    if(it == o->props.end() || it->second.fType != eVK_Unistring) return "<none>";
    return narrow(u16(it->second.uValue.fString.fString, it->second.uValue.fString.fLength));
}

int prop_bool(Obj *o, const char *key) {
    auto it = o->props.find(widen(key));
    if(it == o->props.end() || it->second.fType != eVK_Boolean) return -1;
    return it->second.uValue.fBoolean ? 1 : 0;
}

void put_bool(Obj *o, const char *key, bool b) {
    PA_Variable v = undefined_var();
    PA_SetBooleanVariable(&v, b);
    put(o, key, v);
}

const std::string kData = "synthetic document to be timestamped";

/* ---------- LIVE defects ---------- */

/* LIVE: Create timestamp query -> ob_get_a never cleared the owned copy of options.policy. */
bool defect_live_create_query_policy_not_cleared() {
    Obj *o = new_object(false);
    put_text(o, "policy", "1.2.3.4.1");
    put_real(o, "hash", 2);
    put_real(o, "format", 1);
    std::string der = call_create_query(kData, o);
    TS_REQ *q = parse_query(der);
    bool ok = check(q != NULL, "DER query returned");
    ok &= check(q && policy_of(q) == "1.2.3.4.1", "policy honoured");
    ok &= check(q && md_nid_of(q) == NID_sha256, "sha256 honoured");
    TS_REQ_free(q);
    ok &= check(g_objects.count(o) && o->rc == 1, "caller's options object untouched");
    release_object(o);
    return no_leaks() && ok;
}

/* LIVE: ob_get_n/ob_get_b never cleared a wrong-kind copy of format/hash/cert/no_nonce
   (a string copy leaks; an object/collection reference is never released). */
bool defect_live_create_query_wrong_kind_options_not_cleared() {
    Obj *o = new_object(false);
    put_text(o, "format", "asn1");
    put_text(o, "hash", "sha256");
    put_object(o, "cert", false);
    put_object(o, "no_nonce", true);
    std::string out = call_create_query(kData, o);
    /* wrong kinds read as 0/false: text format, sha512, no cert, nonce */
    bool ok = check(out.find("Version: 1") != std::string::npos, "text query returned");
    ok &= check(out.find("sha512") != std::string::npos, "default hash");
    ok &= check(out.find("Certificate required: no") != std::string::npos, "cert false");
    ok &= check(out.find("Nonce: unspecified") == std::string::npos, "nonce present");
    release_object(o);
    return no_leaks() && ok;
}

/* LIVE: Verify timestamp request -> ob_get_a/ob_get_posix_path never cleared the
   owned copies of capath/cafile/castore/untrusted. */
bool defect_live_verify_path_options_not_cleared() {
    Obj *o = new_object(false);
    put_text(o, "capath", "Macintosh HD:nonexistent:certs:");
    put_text(o, "cafile", "Macintosh HD:nonexistent:ca.pem");
    put_text(o, "castore", "Macintosh HD:nonexistent:store");
    put_text(o, "untrusted", "Macintosh HD:nonexistent:untrusted.pem");
    Obj *r = call_verify("not a TS_RESP", "not a TS_REQ", o);
    bool ok = check(r && prop_bool(r, "success") == 0, "malformed input is not verified");
    ok &= check(g_objects.count(o) && o->rc == 1, "caller's options object untouched");
    if(r) release_object(r);
    release_object(o);
    return no_leaks() && ok;
}

/* HARDENING (LIVE helpers): on error PA_GetObjectProperty leaves its result
   uninitialised. ob_get_a (policy, capath, cafile, castore, untrusted),
   ob_get_n (format, hash) and ob_get_b (cert, no_nonce) must neither read
   nor clear it. */
bool hardening_live_ob_get_error_result_untouched() {
    Obj *o = new_object(false);
    put_text(o, "policy", "1.2.3.4.1");
    put_real(o, "hash", 2);
    put_bool(o, "cert", true);
    CUTF8String s;
    g_fail_key = "policy";
    ob_get_a((PA_ObjectRef)o, L"policy", &s);
    g_fail_key = "hash";
    double d = ob_get_n((PA_ObjectRef)o, L"hash");
    g_fail_key = "cert";
    bool b = ob_get_b((PA_ObjectRef)o, L"cert");
    g_fail_key.clear();
    release_object(o);
    bool ok = check(s.empty(), "uninitialised result not read as text");
    ok &= check(d == 0.0 && !b, "failed reads yield defaults");
    return no_leaks() && ok;
}

/* ---------- DORMANT defects / HARDENING (support/4DPlugin-JSON.cpp, no caller) ---------- */

/* The retained object/collection reference was never released, so it
   outlived its owner. The returned ref is borrowed from the parent. */
bool defect_dormant_ob_get_o_c_reference_not_released() {
    Obj *o = new_object(false);
    Obj *child = put_object(o, "child", false);
    Obj *items = put_object(o, "items", true);
    PA_ObjectRef r1 = ob_get_o((PA_ObjectRef)o, L"child");
    PA_CollectionRef r2 = ob_get_c((PA_ObjectRef)o, L"items");
    bool ok = check(r1 == (PA_ObjectRef)child && r2 == (PA_CollectionRef)items, "references returned");
    ok &= check(child->rc == 1 && items->rc == 1, "returned references borrowed from the parent");
    release_object(o);
    return no_leaks() && ok;
}

/* HARDENING: ob_stringify cleared (and read) the 1217 result without checking the error. */
bool hardening_ob_stringify_error_untouched() {
    Obj *o = new_object(false);
    put_text(o, "a", "x");
    g_fail_stringify = true;
    CUTF8String json;
    ob_stringify((PA_ObjectRef)o, &json);
    g_fail_stringify = false;
    release_object(o);
    bool ok = check(json.empty(), "failed stringify yields nothing");
    return no_leaks() && ok;
}

/* ---------- controls (pass on both trees) ---------- */

bool control_create_query_defaults() {
    std::string der = call_create_query(kData, NULL);
    TS_REQ *q = parse_query(der);
    bool ok = check(q != NULL, "DER query returned");
    ok &= check(q && md_nid_of(q) == NID_sha512 && TS_REQ_get_cert_req(q) && !TS_REQ_get_nonce(q) && policy_of(q).empty(), "defaults");
    TS_REQ_free(q);
    return no_leaks() && ok;
}

bool control_create_query_matching_kinds() {
    Obj *o = new_object(false);
    put_real(o, "format", 1);
    put_real(o, "hash", 4);
    put_bool(o, "cert", false);
    put_bool(o, "no_nonce", false);
    std::string der = call_create_query(kData, o);
    TS_REQ *q = parse_query(der);
    bool ok = check(q != NULL, "DER query returned");
    ok &= check(q && md_nid_of(q) == NID_sha1 && !TS_REQ_get_cert_req(q) && TS_REQ_get_nonce(q), "options honoured");
    TS_REQ_free(q);
    ok &= check(g_objects.count(o) && o->rc == 1, "caller's options object untouched");
    release_object(o);
    return no_leaks() && ok;
}

bool control_verify_no_options_malformed() {
    Obj *r = call_verify("not a TS_RESP", "not a TS_REQ", NULL);
    bool ok = check(r && prop_bool(r, "success") == 0 && prop_text(r, "tsr") == "<none>", "malformed input");
    if(r) release_object(r);
    return no_leaks() && ok;
}

/* ob_set_s on the result object (tsr/tsq) and the full verify path with a
   synthetic rejected response: nothing leaks, nothing is freed twice. */
bool control_verify_synthetic_rejection() {
    std::string tsq = call_create_query(kData, NULL);
    Obj *r = call_verify(synthetic_rejection(), tsq, NULL);
    bool ok = check(r && prop_bool(r, "success") == 0, "rejection is not verified");
    ok &= check(r && prop_text(r, "tsr").find("Status: Rejected") != std::string::npos, "tsr printed");
    ok &= check(r && prop_text(r, "tsq").find("Version: 1") != std::string::npos, "tsq printed");
    if(r) release_object(r);
    return no_leaks() && ok;
}

bool control_ob_set_get_round_trip() {
    Obj *o = new_object(false);
    ob_set_n((PA_ObjectRef)o, L"n", 2.5);
    ob_set_b((PA_ObjectRef)o, L"b", true);
    ob_set_i((PA_ObjectRef)o, L"i", 7);
    ob_set_0((PA_ObjectRef)o, L"z");
    ob_set_s((PA_ObjectRef)o, L"s", "text");
    ob_set_o((PA_ObjectRef)o, L"o", PA_CreateObject());
    ob_set_c((PA_ObjectRef)o, L"c", PA_CreateCollection());
    bool ok = check(o->props.size() == 7, "seven properties set");
    ok &= check(ob_get_n((PA_ObjectRef)o, L"n") == 2.5 && ob_get_b((PA_ObjectRef)o, L"b"), "real and boolean read back");
    ok &= check(ob_is_defined((PA_ObjectRef)o, L"n") && !ob_is_defined((PA_ObjectRef)o, L"x"), "ob_is_defined");
    release_object(o);
    return no_leaks() && ok;
}

bool control_ob_stringify() {
    Obj *o = new_object(false);
    put_text(o, "a", "x");
    CUTF8String json;
    ob_stringify((PA_ObjectRef)o, &json);
    release_object(o);
    bool ok = check(json == (const uint8_t *)"{}", "stringified");
    return no_leaks() && ok;
}

struct Test { const char *name; bool (*fn)(); };
const Test kTests[] = {
    { "defect_live_create_query_policy_not_cleared", defect_live_create_query_policy_not_cleared },
    { "defect_live_create_query_wrong_kind_options_not_cleared", defect_live_create_query_wrong_kind_options_not_cleared },
    { "defect_live_verify_path_options_not_cleared", defect_live_verify_path_options_not_cleared },
    { "hardening_live_ob_get_error_result_untouched", hardening_live_ob_get_error_result_untouched },
    { "defect_dormant_ob_get_o_c_reference_not_released", defect_dormant_ob_get_o_c_reference_not_released },
    { "hardening_ob_stringify_error_untouched", hardening_ob_stringify_error_untouched },
    { "control_create_query_defaults", control_create_query_defaults },
    { "control_create_query_matching_kinds", control_create_query_matching_kinds },
    { "control_verify_no_options_malformed", control_verify_no_options_malformed },
    { "control_verify_synthetic_rejection", control_verify_synthetic_rejection },
    { "control_ob_set_get_round_trip", control_ob_set_get_round_trip },
    { "control_ob_stringify", control_ob_stringify },
};

} // namespace

int main(int argc, char **argv) {
    gCall4D = engine;
    if(argc == 2 && !strcmp(argv[1], "--list")) {
        for(const Test &t : kTests) printf("%s\n", t.name);
        return 0;
    }
    if(argc != 2) { fprintf(stderr, "usage: %s --list | <test>\n", argv[0]); return 2; }
    init_plugin();
    for(const Test &t : kTests) {
        if(!strcmp(argv[1], t.name)) {
            bool ok = t.fn();
            printf("%s: %s\n", t.name, ok ? "PASS" : "FAIL");
            return ok ? 0 : 1;
        }
    }
    fprintf(stderr, "unknown test %s\n", argv[1]);
    return 2;
}
