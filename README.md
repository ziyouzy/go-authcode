# go-authcode
authcode的golang实现，会处理好web传输的"/"与"+"问题，为提高性能会尽量规避基于string进行计算与操作，会尽可能基于字节序列、*bytes.Buffer
***
**对于“+”与“/”的问题，采用的替换方式为“+ -> -”,“/ -> _”**
**同时Enocde方法内部在刚刚生成动态密钥时就对动态密钥进行了字符替换操作，也就是说加密工序也是基于替换后的动态密钥完成的**
**因此无论是使用本包进行Decode还是用自定义包进行Decode，用本包所进行加密的数据，并不需考虑使用环境是否为网络环境，不需要对数据的字符进行还原预处理**
**不过用其他autocode工具进行加密的数据，有必要根据不同工具，不同实际情况自己实现数据字符的预处理，此包Decode方法内不包含相关实现**
***
# How To Use

     authcode import "github.com/ziyouzy/go-authcode"
    
    
    /*参数与意义*/
    
    key :="fs06jdlsjflkdjslksjfllkdsg"
    // 加密的key或salt 
    lenKeyC := 1
    // 动态密匙长度，相同的明文会生成不同密文就是依靠动态密匙
    // 加入随机密钥，可以令密文无任何规律，即便是原文和密钥完全相同，加密结果也会每次不同，增大破解难度。
    // 取值越大，密文变动规律越大，密文变化 = 16 的 ckey_length 次方
    expiry :=2
    // 数据过期时间单位为秒
    // 当此值为0时，则数据不会过期
    ac ,_:=authcode.New(key,lenKeyC,expiry)
    // encode ,_ :=ac.Encode(nil,"1234567890abcdefaaaaaa//***/+++____")
    encode ,_ :=ac.Encode([]byte("1234567890abcdefaaaaaa//***/+++____"),"")
    // Encode与Decode方法的入参方式借鉴了内置函数time.Unix(sec int64, nanosec int64).Format("2006-01-02 15:04:05")，其对于秒级时间戳与纳秒级时间戳的处理方式
    // 第一个参数如果不为空则表述对一个字节切片进行加密&解密；第二个参数不为""则代表对一个string字符串进行加密&解密
    // 两者不能“同时为空”或“同时不为空”
    fmt.Println("encode:",encode)//[]byte

    // decode ,_ :=ac.Decode(encode,"")
    decode ,_ :=ac.Decode(nil,string(encode))
    fmt.Println("decode:",decode)//[]byte

    // 清空所有内部字段
    ac.CloseSafe()
