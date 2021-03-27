package go_authcode

import(
	"unicode"
	"regexp"
	"encoding/base64"
	"encoding/hex"
	"crypto/md5"
	"errors"
)



func IsChineseChar(str string) bool {
	for _, r := range str {
		if unicode.Is(unicode.Scripts["Han"], r) || (regexp.MustCompile("[\u3002\uff1b\uff0c\uff1a\u201c\u201d\uff08\uff09\u3001\uff1f\u300a\u300b]").MatchString(string(r))) {
	 		return true
		}
	}
	return false
}


// base64 加密/解密
func Base64_Bytes2Bytes(mode int,bRaw []byte) ([]byte,error) {
	var err error
	switch mode{
	case BASE64_ENCODE:
		buf := make([]byte, base64.StdEncoding.EncodedLen(len(bRaw)))
		base64.StdEncoding.Encode(buf,bRaw)
		return buf,nil
	case BASE64_DECODE:
		dbuf := make([]byte, base64.StdEncoding.DecodedLen(len(bRaw)))
		if n, err := base64.StdEncoding.Decode(dbuf, bRaw); err ==nil{
			return dbuf[:n],nil
		}
	default:
		err =errors.New("unknown mode")
	}
	return nil,err
}

func Base64_String2Bytes(mode int,sRaw string) ([]byte,error) {
	var err error
	switch mode{
	case BASE64_ENCODE:
		buf := make([]byte, base64.StdEncoding.EncodedLen(len(sRaw)))
		base64.StdEncoding.Encode(buf,[]byte(sRaw))
		return buf,nil
	case BASE64_DECODE:
		dbuf := make([]byte, base64.StdEncoding.DecodedLen(len(sRaw)))
		if n, err := base64.StdEncoding.Decode(dbuf, []byte(sRaw)); err ==nil{
			return dbuf[:n],nil
		}
	default:
		err =errors.New("unknown mode")
	}
	return nil,err

}

func Base64_Bytes2String(mode int,bRaw []byte) (string,error) {
	var err error
	switch mode{
	case BASE64_ENCODE:
		return base64.StdEncoding.EncodeToString(bRaw),nil
	case BASE64_DECODE:
		if b, err := base64.StdEncoding.DecodeString(string(bRaw)); err ==nil{
			return string(b),nil
		}
	default:
		err =errors.New("unknown mode")
	}
	return "",err
}

func Base64_String2String(mode int,sRaw string) (string,error) {
	var err error
	switch mode{
	case BASE64_ENCODE:
		return base64.StdEncoding.EncodeToString([]byte(sRaw)),nil
	case BASE64_DECODE:
		if b, err := base64.StdEncoding.DecodeString(sRaw); err ==nil{
			return string(b),nil
		}
	default:
		err =errors.New("unknown mode")
	}
	return "",err
}

// base64_WEB 加密/解密
func Base64_WEB_Bytes2Bytes(mode int,bRaw []byte) ([]byte,error) {
	var err error

	switch mode{
	case BASE64_ENCODE:
		buf := make([]byte, base64.URLEncoding.EncodedLen(len(bRaw)))
		base64.URLEncoding.Encode(buf,bRaw)
		return buf,nil
	case BASE64_DECODE:
		dbuf := make([]byte, base64.URLEncoding.DecodedLen(len(bRaw)))
		if n, err := base64.URLEncoding.Decode(dbuf, bRaw); err ==nil{
			return dbuf[:n],nil
		}
	default:
		err =errors.New("unknown mode")
	}
	return nil,err
}

func Base64_WEB_String2String(mode int,sRaw string) (string,error) {
	var err error
	switch mode{
	case BASE64_ENCODE:
		return base64.URLEncoding.EncodeToString([]byte(sRaw)),nil
	case BASE64_DECODE:
		if b, err := base64.URLEncoding.DecodeString(sRaw); err ==nil{
			return string(b),nil
		}
	default:
		err =errors.New("unknown mode")
	}
	return "",err
}


//生成32位md5字串
func Md5_Bytes2Bytes(bRaw []byte) []byte {
	h := md5.New()//h代表hash
	h.Write(bRaw)
/**
	通过翻阅源码可以看到他并不是对data进行校验计算
	而是对hash.Hash对象内部存储的内容进行校验和
	计算然后将其追加到data的后面形成一个新的byte切片
	因此通常的使用方法就是将data置为nil
*/
	return h.Sum(nil)
}

//生成32位md5字串
func Md5_String2Bytes(sRaw string) []byte {
	h := md5.New()//h代表hash
	h.Write([]byte(sRaw))
	return h.Sum(nil)
}

func Md5_Bytes2Hexstring(bRaw []byte) string {
	h := md5.New()//h代表hash
	h.Write(bRaw)

	return hex.EncodeToString(h.Sum(nil))
}

func Md5_String2Hexstring(sRaw string) string {
	h := md5.New()
	h.Write([]byte(sRaw))

	return hex.EncodeToString(h.Sum(nil))
}