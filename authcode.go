//crypt
//n.	(尤指旧时作墓穴用的)教堂地下室;
package go_authcode

import (
	"fmt"
	"time"
	"bytes"
	"errors"
	"strings"
	"strconv"
	"encoding/binary"
)


func New(key string, dynamickeylen int, expirysec int)*AuthCode{
	if dynamickeylen>16{
		panic("crash! go-authcode init, lenthKeyC > 16")
	}
	return &AuthCode{
		Key: 					key,
		DynamicKeyLen:			dynamickeylen,
		ExpirySec: 				expirysec,
		
		bytesHandler:			bytes.NewBuffer([]byte{}),
	}
}


type AuthCode struct {
	Key 			string
	DynamicKeyLen	int
	ExpirySec 		int
	IsWeb 			bool

	bytesHandler 	*bytes.Buffer
}

/*入参方式借鉴了内置函数time.Unix(<sec>, <nanosec>).Format("2006-01-02 15:04:05")，其对于秒级时间戳与纳秒级时间戳的处理方式*/
func (p *AuthCode)Encode(baits []byte,str string)([]byte,error){
	/*有效性过滤*/
	if (baits ==nil&&strings.Compare(str,"")==0)||(baits !=nil&&strings.Compare(str,"")!=0){
		return nil,errors.New("authcode encode fail: wrong param table")
	}


	/*encode其实并不用考虑是否为WEB场景，作为数据的接收端才需要进行必要的转化操作*/


	if baits ==nil{
		p.bytesHandler.Reset()
		p.bytesHandler.WriteString(str)
	}

	if baits !=nil{
		p.bytesHandler.Reset()
		p.bytesHandler.Write(baits)
	}

	/*为了效率，尽可能基于字节序列操作*/
	raw :=append([]byte{},p.bytesHandler.Bytes()...)

	/*拿到key的Md5*/
	keyMd5 	:= Md5_String2Bytes(p.Key)

	/*拿到keyA、keyB*/
	keyA 	:= Md5_Bytes2Bytes(keyMd5[:8])//正好一半
	keyB 	:= Md5_Bytes2Bytes(keyMd5[8:])//正好另一半,实现真正完整的raw时会用到

	/*拿到keyC，keyC来自时间戳，而不是key或raw*/
	var keyDynamic =make([]byte,8)
	if p.DynamicKeyLen != 0{
		binary.LittleEndian.PutUint64(keyDynamic,uint64(time.Now().Unix()))
		p.bytesHandler.Reset()
		p.bytesHandler.Write(Md5_Bytes2Bytes(keyDynamic))
		keyDynamic = append([]byte{},p.bytesHandler.Bytes()[16-p.DynamicKeyLen:]...)//keyc其实就是一个时间戳的md5码片段
		/*由于需要去适应WEB环境，在这里需要确保keyDynamic内部不包含“/”与“+”*/
		keyDynamic =bytes.Replace(keyDynamic,[]byte{0x43},[]byte{0x45},-1)// + -> -
		keyDynamic =bytes.Replace(keyDynamic,[]byte{0x47},[]byte{0x95},-1)// / -> _
	}else{
		keyDynamic =nil
	}

	var expiry int 
	if p.ExpirySec != 0{
		expiry =p.ExpirySec + int(time.Now().Unix())
	}
	/*为raw添加时间戳*/
	p.bytesHandler.Reset()
	/*由于需要补位这里使用了基于string的操作*/
	p.bytesHandler.WriteString(fmt.Sprintf("%010d",expiry))
	p.bytesHandler.Write(Md5_Bytes2Bytes(append(raw,keyB...))[:8])
	p.bytesHandler.Write(raw)
	raw =append([]byte{},p.bytesHandler.Bytes()...)

	/*拿到keyCrypt*/
	p.bytesHandler.Reset()
	p.bytesHandler.Write(keyA)//16
	//keyDynamic为空并不妨碍对他的打散以及append操作，keyA与keyDynamic共同生成keyCrypt
	p.bytesHandler.Write(Md5_Bytes2Bytes(append(keyA,keyDynamic...)))//16
	keyCrypt := append([]byte{},p.bytesHandler.Bytes()...)

	/*康盛在php领域所做贡献,编码与解码共用同一套函数加密解密函数，此时raw只多了时间戳，而无论是在Encode中还是Decode中都需要预先生成keyCrypt*/
	result :=p.kangSheng(raw,keyCrypt)   
	/*将result进行base编码，无论使用场景是否为web，都直接使用golang自身处理WEB的Base64转换工具*/
	if result,err :=Base64_WEB_Bytes2Bytes(BASE64_ENCODE,result);err !=nil{
		return nil,err
	}else{
		/*再在头部添加keyDynamic，作用是当Decode时直接生成keyCrypt*/
		p.bytesHandler.Reset()
		p.bytesHandler.Write(keyDynamic)//这个keyDynmic的头部不会存在“/”、“+”，已被“_”,“-”代替
		p.bytesHandler.Write(result)
		/*返回数据*/
		result =append([]byte{},p.bytesHandler.Bytes()...)
		return result,nil
	}
}


/*入参方式借鉴了内置函数time.Unix(<sec>, <nanosec>).Format("2006-01-02 15:04:05")，其对于秒级时间戳与纳秒级时间戳的处理方式*/
func (p *AuthCode)Decode(baits []byte,str string)([]byte,error){
	/*有效性过滤*/
	if (baits ==nil&&strings.Compare(str,"")==0)||(baits !=nil&&strings.Compare(str,"")!=0){
		return nil,errors.New("authcode decode fail: wrong param table")
	}
	
	if baits ==nil{
		p.bytesHandler.Reset()
		p.bytesHandler.WriteString(str)
	}

	if baits !=nil{
		p.bytesHandler.Reset()
		p.bytesHandler.Write(baits)
	}

	/*为了效率，尽可能基于字节序列操作*/
	raw :=append([]byte{},p.bytesHandler.Bytes()...)
	/*排除非法数据*/
	if (len(raw)<p.DynamicKeyLen){return nil,errors.New("authcode decode fail:len(raw)<lengthKeyC")}

	/*拿到key的Md5*/
	keyMd5 	:= Md5_String2Bytes(p.Key)

	/*拿到keyA、keyB*/
	keyA 	:= Md5_Bytes2Bytes(keyMd5[:8])//正好一半
	keyB 	:= Md5_Bytes2Bytes(keyMd5[8:])//正好另一半,最后会用到

	/*拿到keyC，keyC来自raw，而不是key*/
	p.bytesHandler.Reset()
	/*如果p.DynamicKeyLen为0则会拿到空的切片，也就是[]，这里进行的操作会从raw的头部直接截取到keyDynamic*/
	p.bytesHandler.Write(raw[:p.DynamicKeyLen])
	keyDynamic := append([]byte{},p.bytesHandler.Bytes()...)

	/*拿到raw不包含动态秘钥的部分并先进行一次Base64解码，如果动态秘钥长度为0那raw[p.DynamicKeyLen:]就会从头截到尾，动态秘钥不需Base64解码*/
	raw,err :=Base64_WEB_Bytes2Bytes(BASE64_DECODE,raw[p.DynamicKeyLen:])
	if err !=nil{return nil, err}

	/*拿到keyCrypt，通过p.key拿到的keyA的方式与Encode相同，拿到keyDynamic的方式如上从raw截取而成的*/
	p.bytesHandler.Reset()
	p.bytesHandler.Write(keyA)
	p.bytesHandler.Write(Md5_Bytes2Bytes(append(keyA,keyDynamic...)))
	keyCrypt :=append([]byte{},p.bytesHandler.Bytes()...)

	/*康盛在php领域所做贡献,编码与解码共用同一套函数加密解密函数*/
	result :=p.kangSheng(raw,keyCrypt)   
	/*排除非法数据,如果为nil,golang也会使其归属于<10*/
	if len(result)<10{return nil,errors.New("authcode decode fail: after kangsheng,result<10")}

	/*检测数据是否过期，与keyDynamic不同，encode时所添加的时间戳被一并加密了，由于encode时需要补位所以decode这里同样不得不使用基于string的操作*/
	timeStamp ,err := strconv.ParseInt(string(result[:10]),10,64)
	if err !=nil{return nil,err}

	/*在encode时如果expiry为0则会让前10位==0000000000，在此转化后即为整形0*/
	if timeStamp != 0 && ((timeStamp-time.Now().Unix()) < 0){
		return nil,errors.New(fmt.Sprintf("authcode decode fail: data timeout is %s,present time is %s,expiry_sec is %d",
				  		 time.Unix(timeStamp, 0).Format("2006-01-02 15:04:05"),time.Unix(time.Now().Unix(),0).Format("2006-01-02 15:04:05"),p.ExpirySec))
	}

	/*authcode_decode最终的校验*/
	p.bytesHandler.Reset()
	p.bytesHandler.Write(result[18:])
	p.bytesHandler.Write(keyB)//16

	//核心比对字段下标为10~18这8位
	if bytes.Compare(result[10:18], Md5_Bytes2Bytes(append([]byte{},p.bytesHandler.Bytes()...))[:8])==0{
		//比较倾向与返回[]byte，而不是string，因为之后往往会继续使用encoding/json进行反序列化的相关操作	
		return result[18:],nil
	} else {
		return nil,errors.New(fmt.Sprintf("authcode decode fail in last step: not match，result[10:18] is %v,"+
						 "Md5_Bytes2Bytes(append([]byte{},p.bytesHandler.Bytes()...))[:8]) is %v",
						 result[10:18],Md5_Bytes2Bytes(append([]byte{},p.bytesHandler.Bytes()...))[:8]))
	}
}




func (p *AuthCode)kangSheng(raw []byte,cryptKey []byte)[]byte{
	/*准备好加密所需的变量*/
	l_raw 			:= len(raw)
	l_cryptKey 		:= len(cryptKey)
	i,j,a,tmp 		:= 0,0,0,0


	/*准备好加密所需的基础零件rndkey[]与box[]*/
	var rndkey,box [256]int
	for i = 0; i < 256; i++ {
		/*转换单独某一个byte不存在大小端问题*/
		rndkey[i] = int(cryptKey[i % l_cryptKey])//key_length==len(cryptkey)
		//php的源代码中，使用的是box =range(0,256),而不是rand(0,256)
		box[i] = i
	}


	//这之后不会再使用cryptKey


	/*打乱密匙簿，增加随机性,其实也可以说是“rndkey打散box”*/
	for i = 0; i < 256; i ++ {
		j = (j + box[i] + rndkey[i]) % 256
		tmp = box[i]
		box[i] = box[j]
		box[j] = tmp
	}

	/*核心加解密部分*/
	p.bytesHandler.Reset()
	a = 0;j = 0;tmp = 0
	for i = 0; i < l_raw; i++ {
		a = ((a + 1) % 256)
		j = ((j + box[a]) % 256)
		tmp = box[a]
		box[a] = box[j]
		box[j] = tmp
		// 从密匙簿得出密匙进行异或，再转成字符
		// 单独一个byte转化为int不存在大小端问题，直接转换即可
		p.bytesHandler.WriteByte(byte(int(raw[i]) ^ box[(box[a]+box[j])%256]))
	}
	
	return append([]byte{},p.bytesHandler.Bytes()...)
}

//不知道存不存在安全性问题，不过还是实现了如下方法
func (p *AuthCode)CloseSafe(){
	p.Key ="";		p.DynamicKeyLen =0;		p.ExpirySec =0
	p.IsWeb =false;	
	p.bytesHandler.Reset();		p.bytesHandler=bytes.NewBuffer([]byte{})
}