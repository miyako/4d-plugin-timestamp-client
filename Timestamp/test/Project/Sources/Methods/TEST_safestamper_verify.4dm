//%attributes = {}
$path:=Get 4D folder:C485(Current resources folder:K5:16)+"safestamper.com"+Folder separator:K24:12

$cafile:=$path+"SafeStamper_TSA.cer"
$untrusted:=$path+"SafeStamper_TSA.cer"

DOCUMENT TO BLOB:C525($path+"sample.tsq";$TSQ)
DOCUMENT TO BLOB:C525($path+"sample.tsr";$TSR)

$params:=New object:C1471("cafile";$cafile;"untrusted";$untrusted)

$status:=Verify timestamp request ($TSR;$TSQ;$params)

If ($status.success)
	TRACE:C157
End if 
