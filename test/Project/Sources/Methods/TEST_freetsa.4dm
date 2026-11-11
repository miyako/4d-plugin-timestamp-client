//%attributes = {}
  //data to hash
$path:=Get 4D folder:C485(Current resources folder:K5:16)+"4D.pdf"
DOCUMENT TO BLOB:C525($path;$PDF)

If (True:C214)
	  //this is the default when params is empty
	$params:=New object:C1471(\
		"cert";True:C214;\
		"no_nonce";True:C214;\
		"format";Timestamp Request ASN1;\
		"hash";Timestamp Hash Algorithm SHA512)
End if 

C_BLOB:C604($TSQ;$TSR)

$TSQ:=Create timestamp query ($PDF;$params)

ARRAY TEXT:C222($hn;1)
ARRAY TEXT:C222($hv;1)

$hn{1}:="Content-Type"
$hv{1}:="application/timestamp-query"

$status:=HTTP Request:C1158(HTTP POST method:K71:2;"https://freetsa.org/tsr";$TSQ;$TSR;$hn;$hv)

ASSERT:C1129($status=200)

$capath:=Get 4D folder:C485(Current resources folder:K5:16)+"freetsa.org"+Folder separator:K24:12

$cafile:=$capath+"cacert.cer.der"

$params:=New object:C1471("cafile";$cafile)

$verify:=Verify timestamp request ($TSR;$TSQ;$params)

ASSERT:C1129($verify.success)

$cafile:=$capath+"cacert.cer.pem"

$params:=New object:C1471("cafile";$cafile)

$verify:=Verify timestamp request ($TSR;$TSQ;$params)

ASSERT:C1129($verify.success)
