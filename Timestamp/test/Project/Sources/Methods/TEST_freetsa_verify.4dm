//%attributes = {}
$path:=Get 4D folder:C485(Current resources folder:K5:16)+"freetsa.org"+Folder separator:K24:12

$cafile:=$path+"cacert.pem"
$untrusted:=$path+"tsa.crt"

DOCUMENT TO BLOB:C525($path+"sample.tsq";$TSQ)
DOCUMENT TO BLOB:C525($path+"sample.tsr";$TSR)

$params:=New object:C1471("cafile";$cafile)

$status:=Verify timestamp request ($TSR;$TSQ;$params)

If ($status.success)
	TRACE:C157
End if 
