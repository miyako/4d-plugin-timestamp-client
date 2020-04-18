//%attributes = {}
  //data to hash
$path:=Get 4D folder:C485(Current resources folder:K5:16)+"4D.pdf"
DOCUMENT TO BLOB:C525($path;$PDF)

$params:=New object:C1471(\
"cert";False:C215;\
"no_nonce";False:C215;\
"format";Timestamp Request ASN1;\
"hash";Timestamp Hash Algorithm SHA256)

C_BLOB:C604($TSQ;$TSR)

$TSQ:=Create timestamp query ($PDF;$params)

ARRAY TEXT:C222($hn;1)
ARRAY TEXT:C222($hv;1)

$hn{1}:="Content-Type"
$hv{1}:="application/timestamp-query"

$status:=HTTP Request:C1158(HTTP POST method:K71:2;"https://safestamper.com/tsa";$TSQ;$TSR;$hn;$hv)

ASSERT:C1129($status=200)

$capath:=Get 4D folder:C485(Current resources folder:K5:16)+"safestamper.com"+Folder separator:K24:12

$cafile:=$capath+"SafeStamper_TSA.cer"
$untrusted:=$capath+"SafeStamper_TSA.cer"  //not needed if tsq was created with "cert" (default)

$params:=New object:C1471("cafile";$cafile;"untrusted";$untrusted)

$verify:=Verify timestamp request ($TSR;$TSQ;$params)

ASSERT:C1129($verify.success)

$params:=New object:C1471("capath";$capath;"untrusted";$untrusted)

$verify:=Verify timestamp request ($TSR;$TSQ;$params)

ASSERT:C1129($verify.success)