//%attributes = {}
  //data to hash
$path:=Get 4D folder:C485(Current resources folder:K5:16)+"4D.pdf"
DOCUMENT TO BLOB:C525($path;$PDF)

If (True:C214)
	  //this is the default when params is empty
	$params:=New object:C1471(\
		"cert";False:C215;\
		"no_nonce";True:C214;\
		"format";Timestamp Request ASN1;\
		"hash";Timestamp Hash Algorithm SHA1)
End if 

C_BLOB:C604($TSQ;$TSR)

$TSQ:=Create timestamp query ($PDF;$params)

ARRAY TEXT:C222($hn;1)
ARRAY TEXT:C222($hv;1)

$hn{1}:="Content-Type"
$hv{1}:="application/timestamp-query"

$status:=HTTP Request:C1158(HTTP POST method:K71:2;"http://timestamp.apple.com/ts01";$TSQ;$TSR;$hn;$hv)

$capath:=Get 4D folder:C485(Current resources folder:K5:16)+"apple.com"+Folder separator:K24:12

$cafile:=$capath+"Apple Root Certificate Authority.cer.pem"
$cafile:=$capath+"Apple Timestamp Certification Authority.cer.pem"

$params:=New object:C1471("cafile";$cafile)

$verify:=Verify timestamp request ($TSR;$TSQ;$params)

ASSERT:C1129($verify.success)