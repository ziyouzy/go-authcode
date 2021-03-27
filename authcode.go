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


func New(key string, lengthkeyc int, expirysec int, isweb bool)(*AuthCode,error){
	/*可以==0的是expireSec而不是lengthKeyC*/
	if lengthkeyc>16||lengthkeyc<=0{
		return nil,errors.New("must 0 < lenthKeyC <= 16")
	}
	return &AuthCode{
		key: 				key,
		lengthKeyC:			lengthkeyc,
		expirySec: 			expirysec,
		isWeb: 				isweb,
		transfor1:			[2][]byte{[]byte("*"), []byte("+")},
		transfor2:			[2][]byte{[]byte("_"), []byte("/")},
		bytesHandler:		bytes.NewBuffer([]byte{}),
	},nil
}


type AuthCode struct {
	key 			string
	lengthKeyC		int
	expirySec 		int

	isWeb 			bool
	transfor1		[2][]byte
	transfor2		[2][]byte
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
	keyMd5 	:= Md5_String2Bytes(p.key)

	/*拿到keyA、keyB*/
	keyA 	:= Md5_Bytes2Bytes(keyMd5[:8])//正好一半
	keyB 	:= Md5_Bytes2Bytes(keyMd5[8:])//正好另一半,实现真正完整的raw时会用到

	/*拿到keyC，keyC来自时间戳，而不是key或raw*/
	var keyC =make([]byte,8)
	binary.LittleEndian.PutUint64(keyC,uint64(time.Now().Unix()))
	p.bytesHandler.Reset()
	p.bytesHandler.Write(Md5_Bytes2Bytes(keyC))
	keyC = append([]byte{},p.bytesHandler.Bytes()[16-p.lengthKeyC:]...)//keyc其实就是一个时间戳的md5码片段

	var expiry int 
	if p.expirySec != 0{
		expiry =p.expirySec + int(time.Now().Unix())
	}

	/*实现真正完整的raw*/
	p.bytesHandler.Reset()
	p.bytesHandler.WriteString(fmt.Sprintf("%010d",expiry))
	p.bytesHandler.Write(Md5_Bytes2Bytes(append(raw,keyB...))[:8])
	p.bytesHandler.Write(raw)
	raw =append([]byte{},p.bytesHandler.Bytes()...)

	/*拿到keyCrypt*/
	p.bytesHandler.Reset()
	p.bytesHandler.Write(keyA)//16
	p.bytesHandler.Write(Md5_Bytes2Bytes(append(keyA,keyC...)))//16
	keyCrypt := append([]byte{},p.bytesHandler.Bytes()...)

	/*康盛在php领域所做贡献,result的长度必然是256*/
	result :=p.kangSheng(raw,keyCrypt)   

	/*先将result进行base编码*/
	if result,err :=Base64_Bytes2Bytes(BASE64_ENCODE,result);err !=nil{
		return nil,err
	}else{
		/*再在头部添加KeyC，keyC只是个时间标识*/
		p.bytesHandler.Reset()
		p.bytesHandler.Write(keyC)
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

	/*虽然golang拥有针对性的相关方法(base64.URLEncoding.EncodeToString)，但是还是感觉直接转化一下会方便一些*/
	if p.isWeb{
		if baits ==nil{
			str = strings.Replace(str, "*", "+", -1)
			str = strings.Replace(str, "_", "/", -1)
			p.bytesHandler.Reset()
			p.bytesHandler.WriteString(str)
		}

		if baits !=nil{
			/*需要加密的原始数据内有"*"或"+"，并不代表加密后的数据还会有"*"或"+"，在这里所操作的是加密后的数据*/
			baits = bytes.Replace(baits, p.transfor1[0], p.transfor1[1], -1)
			baits = bytes.Replace(baits, p.transfor2[0], p.transfor2[1], -1)
			p.bytesHandler.Reset()
			p.bytesHandler.Write(baits)
		}
	}else{
		if baits ==nil{
			p.bytesHandler.Reset()
			p.bytesHandler.WriteString(str)
		}

		if baits !=nil{
			p.bytesHandler.Reset()
			p.bytesHandler.Write(baits)
		}
	}

	/*为了效率，尽可能基于字节序列操作*/
	raw :=append([]byte{},p.bytesHandler.Bytes()...)
	/*排除非法数据*/
	if (len(raw)<p.lengthKeyC){return nil,errors.New("authcode decode fail:len(raw)<lengthKeyC")}

	/*拿到key的Md5*/
	keyMd5 	:= Md5_String2Bytes(p.key)

	/*拿到keyA、keyB*/
	keyA 	:= Md5_Bytes2Bytes(keyMd5[:8])//正好一半
	keyB 	:= Md5_Bytes2Bytes(keyMd5[8:])//正好另一半,最后会用到

	/*拿到keyC，keyC来自raw，而不是key*/
	p.bytesHandler.Reset()
	p.bytesHandler.Write(raw[:p.lengthKeyC])
	keyC := append([]byte{},p.bytesHandler.Bytes()...)
	
	/*拿到raw的真正有价值部分*/
	raw,err :=Base64_Bytes2Bytes(BASE64_DECODE,raw[p.lengthKeyC:])
	if err !=nil{return nil, err}

	/*拿到keyCrypt*/
	p.bytesHandler.Reset()
	p.bytesHandler.Write(keyA)
	p.bytesHandler.Write(Md5_Bytes2Bytes(append(keyA,keyC...)))
	keyCrypt :=append([]byte{},p.bytesHandler.Bytes()...)

	/*康盛在php领域所做贡献,result的长度必然是256*/
	result :=p.kangSheng(raw,keyCrypt)   
	/*排除非法数据,如果为nil,golang也会使其归属于<10*/
	if len(result)<10{return nil,errors.New("authcode decode fail: after kangsheng,result<10")}

	/*检测数据是否过期,uint64最多只能容纳8个长度的bytes*/
	timeStamp ,err := strconv.ParseInt(string(result[:10]),10,64)
	if err !=nil{return nil,err}

	/*在encode时如果expiry为0则会让前10位==0000000000，在此转化后即为整形0*/
	if timeStamp != 0 && ((timeStamp-time.Now().Unix()) < 0){
		return nil,errors.New(fmt.Sprintf("authcode decode fail: data timeout is %s,present time is %s,expiry_sec is %d",
				  		 time.Unix(timeStamp, 0).Format("2006-01-02 15:04:05"),time.Unix(time.Now().Unix(),0).Format("2006-01-02 15:04:05"),p.expirySec))
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
	p.key ="";		p.lengthKeyC =0;		p.expirySec =0
	p.isWeb =false;	
	p.bytesHandler.Reset();		p.bytesHandler=bytes.NewBuffer([]byte{})
}