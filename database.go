package synchro

import (
		"github.com/golangdaddy/go-tools-essential"
		"github.com/golangdaddy/go-zencode"
		"github.com/mreiferson/go-httpclient"
		"bytes"
		"sync"
		"crypto/rand"
		"crypto/ecdsa"
		"strings"
		"io/ioutil"
		"net/http"
		"time"
		"fmt"
		)
		
type Signature struct {
	parent string
	child string
	Signed string
	A string
	B string
	X string
}

func (child *OBJ) NewSignature(parent_id string, signed_by *OBJ, private_key *ecdsa.PrivateKey) *Signature {
	for {
		sig := &Signature{}
		sig.parent = parent_id
		sig.child = child.ID()
		_, target_hash := tools.SHA(1, 0, sig.parent+sig.child, nil)
		sig.Signed = signed_by.PublicName()
		a, b, err := ecdsa.Sign(rand.Reader, private_key, target_hash); if err != nil { signed_by.i.Error("*OBJ: "+err.Error()); break }
		sig.A = a.String()
		sig.B = b.String()
		return sig
	}
	signed_by.i.logs<-"CREATE NEW SIGNATURE FAILED"; return nil
}
		
type Index struct {
	Objects map[string]*Signature
	X map[string]*Index
	sync.RWMutex
}
		
func (index *Index) New() *Index {
	i := &Index{}
	i.Objects = make(map[string]*Signature)
	i.X = make(map[string]*Index)
	return i
}
		
func (i *Infrastructure) ReadObject(id string) *OBJ {
	i.RLock()
		obj := i.Storage.Objects[id]
	i.RUnlock()
	for {
		if obj != nil {
			if obj.Data == nil { i.logs<-"READOBJECT: FAILED, DATA IS CORRUPTED"; break }
			return obj
		}
		ok, s := i.Read(id); if !ok { break }
		o := &OBJ{}
		o.Data = zencode.Decode(i.logs, s)
		if o.Data == nil { i.logs<-"READOBJECT: FAILED, NIL OBJECT DATA FROM "+s; break }
		o.i = i
		if !o.Digest() { break; }
		go func() {
			i.Lock()
				i.Storage.Objects[id] = o
			i.Unlock()
			time.Sleep(333)
			i.Lock()
				delete(i.Storage.Objects, id)
			i.Unlock()
		}()
		return o
	}
	i.logs<-"READOBJECT: FAILED "+id
	return nil
}

func (i *Infrastructure) Read(id string) (bool, string) {
	for tools.Digest_valid(i.logs, id) {
		i.RLock()
			s := i.Storage.Data[id]
		i.RUnlock()
		// already in database
		if len(s) > 0 { if tools.SHA_256(s) == id { return true, s } }
		// import from external objects store
		path := i.Deployment.Core["paths"]["object_db"]+id
		ok := false
		if i.Storage.Local {
			path = "./OBJECTS"+path[strings.LastIndex(path, "/"):]
			b := []byte{}
			ok, b = tools.File_read_bytes(i.logs, path)
			if ok {
				ok, b = tools.Crypt_aes(i.logs, false, i.root_secret, b)
				s = string(b)
			}
		} else {
			ok, s = tools.URL_get(i.logs, path+".json")
			if s == "null" { i.logs<-"READ: RETURNING NULL FROM DATABASE"; break }
			if ok { s = s[1:(len(s)-2)] }
		}
		if !ok { break }
		current := tools.SHA_256(s)
		if current != id { i.logs<-"READ: ID DIGEST MISMATCH"; break }
		i.Lock()
			i.Storage.Data[id] = s
		i.Unlock()
		return true, s
	}
	i.logs<-"READ: FAILED TO READ OBJECT "+id; return false, ""
}

func (i *Infrastructure) DeleteFromIndex(path, id string) bool {
	i.logs<-"*Database: DELETING FROM INDEX "+path+" "+id[0:8]
	ok, _, index := i.GetIndex(path);
	if ok {
		new_list := make(map[string]*Signature)
		index.RLock()
			for object_id, index_sig := range index.Objects { if object_id != id { new_list[object_id] = index_sig } }
		index.RUnlock()
		index.Lock()
			index.Objects = new_list
		index.Unlock()
		return i.backup_index()
	}
	return false
}

func (i *Infrastructure) Create(R *Request) {
	if len(R.input["taxonomy"]) < 64 { ok, o := R.Create(); if ok { if o.CloneTo(R.input["taxonomy"]) { i.BroadcastObject(o.ID()); return } } }
	i.logs<-"*Database: FAILED TO EXECURE STORE ON NEW OBJECT"
}

func (i *Infrastructure) IndexObjects(path string) map[string]*Signature {
	ok, taxonomy, index := i.GetIndex(path)
	i.logs<-"INDEXOBJECTS: LISTING TAXONOMY "+taxonomy
	if ok {
		index.RLock()
			for id, _ := range index.Objects { i.logs<-"INDEXOBJECTS: "+id }
		index.RUnlock()
		return index.Objects
	}
	i.logs<-"*Database: NO OBJECTS IN NIL INDEX"
	return nil
}

func (i *Infrastructure) PointerObjects(parent_id, type_id string) map[string]interface{} {
	new_list := make(map[string]interface{})
	for {
		ok, map_bytes := tools.URL_get_bytes(i.logs, i.Deployment.Core["paths"]["pointer_db"]+parent_id+"/"+type_id+".json"); if !ok { break }
		if !tools.Decode_json(i.logs, map_bytes, &new_list) { break }
		i.logs<-"POINTEROBJECTS: RETURNING MAP OF "+tools.IntToString(len(new_list))+" SIGNATURES"
		return new_list
	}
	i.logs<-"POINTEROBJECTS: FAILED TYPE "+type_id
	return nil
}

func (i *Infrastructure) GetIndex(path string) (bool, string, *Index) {
	if len(path) > 0 {
		path = strings.ToLower(path)
		if string(path[0]) != "/" { path = "/"+path }
		p := strings.Split(path, "/")[1:]
		if len(p) > 0 {
			c := []string{}
			for _, cc := range p {
				if len(cc) == 0 { continue }
				ok, cat := tools.Parse_safe(i.logs, cc); if !ok { i.logs<-"*Database: GET INDEX ABORTING ON INVALID PATH "+path; return false, "", nil }
				c = append(c, cat)
			}
			if len(c) >= 1 { return true, path, i.CreateIndex(c) }
		}
	}
	i.logs<-"*Infrastructure: FAILED GET INDEX "+path
	return false, "", nil
}

func (i *Infrastructure) CreateIndex(a []string) *Index {
	p := make([]*Index, len(a))
	if i.Storage.Index[a[0]] == nil { i.Storage.Index[a[0]] = (&Index{}).New() }
	p[0] = i.Storage.Index[a[0]]
	taxpath := ""
	for x, tax := range a {
		taxpath += "/"+tax
		if (x-1) < 0 { continue }
		new_index := (&Index{}).New()
		i.RLock()
			index := p[x-1].X[tax]
		i.RUnlock()
		if index == nil {
			i.Lock()
				p[x-1].X[tax] = new_index
			i.Unlock()
			p[x] = new_index
		} else {
			p[x] = p[x-1].X[tax]
		}
	}
	index := p[len(a)-1]
	if index == nil { tools.Quit_slow(i.logs, "*Database: FAILED TO GET VALID INDEX") }
	if index.X == nil {
		i.Lock()
			index.X = make(map[string]*Index)
		i.Unlock()
	}
	if index.Objects == nil {
		i.Lock()
			index.Objects = make(map[string]*Signature)
		i.Unlock()
	}
	return index
}

func (o *OBJ) Store() bool {
	go o.i.backup_object(o)
	o.c = make(chan bool)
	o.i.Storage.backup_channel <- o
	complete := <- o.c
	if complete { return true }
	o.i.logs<-"STORE: FINISHED FAIL "+o.ShortID()
	return false
}

func (o *OBJ) CloneTo(array interface{}) bool {
	o.Digest()
	for array != nil {
		id_list := []string{}
		fail := false
		ok := false
		switch v := array.(type) {
			case *OBJ: obj, ok := array.(*OBJ); if !ok { break }; id_list = append(id_list, obj.id)
			case string: id, ok := array.(string); if !ok { fail = true; break }; id_list = append(id_list, id)
			case []string: id_list, ok = array.([]string); if !ok { fail = true; break }
			case []*OBJ: obj_array, ok := array.([]*OBJ); if !ok { fail = true; break }; for _, new_parent := range obj_array { id_list = append(id_list, new_parent.id) }
			default: fmt.Println(v)
		}
		if fail { break }
		o.Lock()
			if o.z == nil { o.z = make(map[string]*Signature) }
		o.Unlock()
		for _, id := range id_list {
			ok, private_key, _ := o.i.UnlockCertificate(o.i.RootAuthority, "ECDSA", ""); if !ok { tools.Quit_slow(o.i.logs, "CANT GET CACHED SUPER USER ECDSA KEY") }
			sig := o.NewSignature(id, o.i.RootAuthority, private_key)
			o.Lock()
				o.z[id] = sig
			o.Unlock()
		}
		if fail { return false }
		return o.Store()
	}
	o.i.Error("*OBJ: CLONE OBJECT FAILED")
	return false
}

func (o *OBJ) ChildObjects(path string, limit int) []*OBJ {
	list := []*OBJ{}
	for {
		if o.Index == nil { break }
		if o.Index[path] == nil { break }
		if o.Index[path].Objects == nil { break }
		for id, signature := range o.Index[path].Objects {
			obj := o.i.ReadObject(id)
			if obj != nil {
				if !o.VerifyChild(signature, id, nil) { continue }
				list = append(list, obj)
			}
			if limit > 0 { if len(list) >= limit { break } }
		}
		break
	}
	o.i.Log("RETURNING "+tools.IntToString(len(list))+" CHILD OBJECTS IN "+path);
	return list
}

func (i *Infrastructure) backup_handler() {
	i.logs<-"BACKUP: STARTED BACKUP HANDLER"
	i.Storage.backup_channel = make(chan *OBJ, 99)
	for {
			o := <- i.Storage.backup_channel
			fail := false
			for dest, signature := range o.z {
				for {
						if tools.Digest_valid(o.i.logs, dest) {
								ok, _ := i.Read(dest); if !ok { fail = true; break }
								if !i.backup_pointer(signature) { fail = true; break }
						} else {
								ok, _, index := o.i.GetIndex(dest); if !ok { fail = true; break }
								index.Lock()
									index.Objects[o.id] = signature
								index.Unlock()
								if !i.backup_index() { fail = true; break }
						}
						break
				}
				if fail { break }
			}
			if o.c != nil { o.c <- !fail }
	}
}

func (i *Infrastructure) backup_pointer(signature *Signature) bool {
	child := i.ReadObject(signature.child); if child == nil { i.logs<-"FAILED TO GET CHILD INFO FOR BACKUP PATH"; return false }
	ok, child_type := child.StrData("_TYPE"); if !ok { i.logs<-"FAILED TO GET CHILD TYPE FOR BACKUP PATH"; return false }
	ok, b := tools.Encode_json(i.logs, signature); if !ok { i.logs<-"*Database: FAILED TO MAKE POINTER BACKUP !!!"; return false }
	return i.send_bytes("PUT", i.Deployment.Core["paths"]["pointer_db"], signature.parent+"/"+child_type+"/"+signature.child, b)
}

func (i *Infrastructure) backup_index() bool {
	key_id := i.RootAuthority.KeyID("ECDSA")
	ok, b := tools.Encode_json(i.logs, i.Storage.Index); if !ok { i.logs<-"*Database: FAILED TO MAKE INDEX BACKUP !!!"; return false }
	return i.send_bytes("PUT", i.Deployment.Core["paths"]["index_db"]+key_id+"/", "", b)
}

func (i *Infrastructure) backup_object(object *OBJ) bool {
	for {
		encoded := zencode.Encode(object.Data)
		digest := tools.SHA_256(encoded)
		b := []byte(encoded)
		if !i.send_bytes("LOCAL", i.Deployment.Core["paths"]["object_db"], digest, b) { break }
		return true
	}
	i.logs<-"*Database: FAILED TO MAKE OBJECT BACKUP !!!"
	return false
}

func (i *Infrastructure) send_bytes(action, host, path string, b []byte) bool {
	if action == "LOCAL" && i.Storage.Local {
		ok, bb := tools.Crypt_aes(i.logs, true, i.root_secret, b)
		if ok { err := ioutil.WriteFile("./OBJECTS/"+path, bb, 0777); if err == nil { return true } }
		i.logs<-"FAILED TO STORE FILE LOCALLY...";
	} else {
		var tsport = &httpclient.Transport {
			ConnectTimeout:        3*time.Second,
			RequestTimeout:        16*time.Second,
			ResponseHeaderTimeout: 6*time.Second,
		}
		for {
			var buf bytes.Buffer
			buf.Write(b)
			full_path := host+path+".json"
			req, err := http.NewRequest(action, full_path, &buf); if err != nil { i.logs<-"BACKUP: "+err.Error(); break }
			response, err := (&http.Client{Transport: tsport}).Do(req); if err != nil { i.logs<-"BACKUP: "+err.Error(); break }
			if response.StatusCode == 200 {
				_, err = ioutil.ReadAll(response.Body); if err != nil { i.logs<-"BACKUP: "+err.Error(); break }
				response.Body.Close()
				tsport.Close()
				return true
			}
			i.logs<-"POST BYTES RECEIVED HTTP RESPONSE ERROR "+response.Status
			break
		}
		tsport.Close()
	}
	i.logs<-"FAILED TO POST BYTES TO "+path
	return false
}
