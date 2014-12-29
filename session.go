package synchro

import(
		"github.com/golangdaddy/go-tools-essential"
		"code.google.com/p/go.net/websocket"
		"crypto/rsa"
		"strings"
		)

type APISocket struct {
	socket *websocket.Conn
	AES_CBC_KEY []byte
	AES_CBC_IV []byte
}
		
type NetSession struct {
	Origin string
	user *OBJ
	username string
	session_key string
	openssl_key map[string]string
	data map[string]map[string]interface{}
	websocket *APISocket
	channel chan string
}

func (session *NetSession) Destroy() {
	session.websocket = nil
	session.user.i.Lock()
		delete(session.user.i.sessions, session.user.PublicName())
	session.user.i.Unlock()
	session.user.i.Error("DESTROYED SESSION OK")
}
func (session *NetSession) GetPublicKey() string { return session.openssl_key["EncodedPublicKey"] }
func (session *NetSession) GetPrivateKey(secret_key string) (bool, *rsa.PrivateKey) {
	ok, _, pk := tools.RecoverKey(session.channel, session.openssl_key["ID"], session.openssl_key["EncryptedPrivateKey"], secret_key); if !ok { session.channel<-"FAILED TO GET USERS TEMP RSA KEY"; return false, nil }
	return true, pk
}
func (session *NetSession) Error(e string) { session.channel<-e }
func (session *NetSession) Errors() chan string { return session.channel }
func (session *NetSession) User() *OBJ { return session.user }
func (session *NetSession) Username() string { return session.user.User() }
func (session *NetSession) Socket() (bool, *websocket.Conn) { sock := session.websocket.socket; if sock == nil { session.Destroy(); return false, nil }; return true, sock }
func (session *NetSession) SocketKey() ([]byte, []byte) { 
	if session.websocket == nil { tools.Quit_slow(session.channel, "SOCKETKEYS: SOCKET DATA IS NIL") }
	return session.websocket.AES_CBC_KEY, session.websocket.AES_CBC_IV
}

func (session *NetSession) New(R *Request) map[string]string {
	session = &NetSession{}
	session.Origin = R.CheckOrigin()
	session.user = R.user
	session.session_key = tools.ID_strong()
	session.data = make(map[string]map[string]interface{})
	session.channel = R.i.Logger.NewLog("SESH:>")
	_, aes_key := tools.SHA(3, 128, tools.Entropy64(), nil)
	session.websocket = &APISocket{nil, aes_key[0:32], aes_key[32:48]}
	// cleanse private keystore
	tokens := make(map[string]string)
	tokens["API_KEY"] = tools.ID_strong()
	tokens["SESSION_KEY"] = session.session_key
	tokens["DEEP_KEY"] = tools.ID_strong()
	ok, openssl_keystore := tools.Generate_openssl(session.channel, R.i.Deployment.RSAKeyLength, tokens["API_KEY"])
	if !ok { tools.Quit_slow(session.channel, "OPEN SSl FAILED TO GEN KEY") }
	session.openssl_key = openssl_keystore
	encoded_pk, ok := session.openssl_key["EncodedPublicKey"]
	if ok {
		tokens["PUBLIC_KEY"] = encoded_pk
		R.i.RegisterSession(session)
		R.Error("CREATED NEW SESSION FOR USER "+R.Username)
	} else { tools.Quit_slow(R.Errors(), "*NetSession: FAILED TO GIVE SESSION PUBLIC KEY") }
	return tokens
}

func (session *NetSession) CheckSessionKey(key string) bool { if session.session_key == key { return true }; return false }

func (session *NetSession) NewSocket(ws *websocket.Conn) *NetSession { session.websocket.socket = ws; return session }

func (session *NetSession) SetData(x, y string, z interface{}) {
	x = strings.ToUpper(x); y = strings.ToUpper(y)
	if session.data[x] == nil { session.data[x] = make(map[string]interface{}) }; session.data[x][y] = z
}
func (session *NetSession) PullData(x, y string) interface{} {
	x = strings.ToUpper(x); y = strings.ToUpper(y)
	if session.data[x] == nil { return nil }; return session.data[x][y]
}

func (session *NetSession) UnlockKey(key_type string, secret_key string, object interface{}) bool {
	for {
		key := session.PullData("keys", "ECDSA"); if key == nil { break }
		ok, decoded_key := tools.Decode_base64(session.channel, key.(string)); if !ok { break }
		ok, plain_bytes := tools.Crypt_aes(session.channel, false, secret_key, decoded_key); if !ok { break }
		if !tools.Decode_gob(session.channel, plain_bytes, object) { break }
		return true
	}
	session.channel<-"FAILED TO UNLOCK SESSION KEY"
	return false
}