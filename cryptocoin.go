package synchro

import (
		"net/http"
		"sync"
		"strings"
		"strconv"
		"github.com/golangdaddy/go-tools-essential"
		"io/ioutil"
		"reflect"
		"time"
		"fmt"
		"os"
		)

func (i *Infrastructure) NewCoinController(coin_name string) *CoinController {
	cc := &CoinController{}
	cc.i = i
	cc.requests = make(chan *CoinRequest, 999)
	cc.CoinName = strings.ToUpper(coin_name)
	cc.TransactionIndex = make(map[string]string)
	cc.Daemons = make(map[string]*OBJ)
	go cc.CoinRequests()
	for id, node_map := range i.Deployment.RPCnodes {
		ok, node := i.NewStringObject(cc.CoinName+"_NODE", node_map)
		if ok {
			cc.Lock()
				cc.Daemons[id] = node
			cc.Unlock()
		}
		cc.i.logs<-"**** CREATED NEW COIN NODE "+id
		r := <- cc.CoinRequest(node, "getinfo", []string{}); if !r.success { continue }
		ok, get_info := interface_to_map(cc.i.logs, r.result); if !ok { continue }
		for x, _ := range get_info { cc.i.logs<-x }
		latest_block, ok := get_info["blocks"].(float64); if !ok { tools.Quit_slow(cc.i.logs, "FAILED TO GET BLOCK POSITION: "+reflect.TypeOf(get_info["blocks"]).String()) }
		cc.LatestBlock = int(latest_block)
	}
	return cc
}

type CoinController struct {
	CoinName string
	LatestBlock int
	Daemons map[string]*OBJ
	Paths map[string]string
	TransactionIndex map[string]string
	requests chan *CoinRequest
	i *Infrastructure
	sync.RWMutex
}

func (cc *CoinController) AnyNode() *OBJ {
	for _, node := range cc.Daemons { return node }
	return nil
}

func (cc *CoinController) CoinRequest(node *OBJ, action string, input interface{}) chan *CoinRequest {
	r := &CoinRequest{}
	r.node = node
	r.action = action
	r.input = input
	r.channel = make(chan *CoinRequest, 2)
	r.success = false
	cc.requests <- r
	return r.channel
}

func (cc *CoinController) AddTransaction(node *OBJ, tx_id string) (bool, *OBJ) {
	cc.RLock()
		transaction := cc.TransactionIndex[tx_id]
	cc.RUnlock()
	if len(transaction) == 64 { return false, nil }
	for {
		r := <- cc.CoinRequest(node, "getrawtransaction", tx_id); if !r.success { break }
		ok, data := interface_to_map(cc.i.logs, r.result); if !ok { break }
		ok, tx := cc.i.NewObject(cc.CoinName+"_TX", data); if !ok { break }
		cc.Lock()
			cc.TransactionIndex[tx_id] = tx.ID()
		cc.Unlock()
		return true, tx
	}
	cc.i.logs<-"*CoinController: FAILED TO ADD TX "+tx_id; return false, nil
}

func (cc *CoinController) StreamTransactionPool() {
	cc.i.logs<-"STREAMING NEW TRANSACTIONS TO DISK"
	for {
			for _, node := range cc.Daemons {
				r := <- cc.CoinRequest(node, "getrawmempool", nil); if !r.success { break }
				data, ok := r.result.([]interface{}); if !ok { break }
				for _, t := range data {
					tx_id, ok := t.(string); if !ok { continue }
					ok, tx := cc.AddTransaction(node, tx_id); if !ok { continue }
					if tx.CloneTo(cc.i.RootAuthority.ID()) { go cc.i.BroadcastObject(tx.ID()) }
				}
			}
	}
}

func (node *OBJ) AuthURL() (bool, string) {
	for {
		ok, user := node.StrData("RPCUSER"); if !ok { break }
		ok, pass := node.StrData("RPCPASS"); if !ok { break }
		ok, host := node.StrData("RPCHOST"); if !ok { break }
		ok, port := node.StrData("RPCPORT"); if !ok { break }
		return true, "http://"+user+":"+pass+"@"+host+":"+port
	}
	node.i.logs<-"*OBJ: FAILED TO GET NODE AUTH URL"
	return false, ""
}

func (node *OBJ) API(method string, params interface{}) (bool, interface{}) {
	for {
		stringinterface := ""
		m := make(map[string]interface{})
		ok, body := node.RPC(map[string]interface{}{"jsonrpc":"2.0", "id":"1", "method":method, "params":params}); if !ok { break }
		if !tools.Decode_json(node.i.logs, body, &m) { if !tools.Decode_json(node.i.logs, body, &stringinterface) { break }; return true, stringinterface }
		if m["result"] == nil { node.i.logs<-"RESPONSE DOES NOT CONTAIN RESULTS"; node.i.logs<-string(body); break }
		switch v := m["result"].(type) {
			case string:
			case int:
			case float64:
			case bool:
			case []interface{}:
			case map[string]interface{}:
			default: node.i.logs<-"RPC: !!!! FAILED INTERFACE SWITCH, TYPE IS: "+reflect.TypeOf(m["result"]).String(); fmt.Println(v); return false, nil
		}
		return true, m["result"]
	}
	node.i.logs<-"RPC: !!!! FAILED"; return false, nil
}

func (node *OBJ) RPC(object interface{}) (bool, []byte) {
	for object != nil {
		ok, data := tools.Encode_json(node.i.logs, object); if !ok { break }
		ok, url := node.AuthURL(); if !ok { break }
		resp, err := http.Post(url, "application/json", strings.NewReader(string(data))); if err != nil { node.i.logs<-"*OBJ: "+err.Error(); break }
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body); if err != nil { node.i.logs<-"*OBJ: SENDNODE "+err.Error(); break }
		return true, body
	}
	node.i.logs<-"*OBJ: FAILED SEND TO NODE"
	return false, nil
}

type CoinRequest struct {
	node *OBJ
	action string
	input interface{}
	result interface{}
	channel chan *CoinRequest
	success bool
}

func (cc *CoinController) CoinRequests() {
	cc.i.logs<-"*CoinCointroller: "+cc.CoinName+" STARTING API CHANNEL HANDLER"
	for {
		ok := false
		r := <- cc.requests
		if r.node == nil { cc.i.logs<-"*CoinController: SUPPLIED NODE IS NIL, SKIPPING !!!!"; continue }
		switch r.action {
			case "getinfo":
					ok, r.result = r.node.API("getinfo", []string{}); if !ok { break }
					r.success = true
			case "getblock":
					block_num, ok := r.input.(int); if !ok { break }
					ok, RPCDATA := r.node.API("getblockhash", []int{block_num}); if !ok { break }
					blockhash, ok := RPCDATA.(string); if !ok { break }
					if !tools.Digest_valid(r.node.i.logs, blockhash) { break }
					ok, r.result = r.node.API("getblock", []string{blockhash}); if !ok { break }
					r.success = true
			case "getrawmempool":
					ok, r.result = r.node.API("getrawmempool", []string{}); if !ok { break }
					r.success = true
			case "getrawtransaction":
					id, ok := r.input.(string); if !ok { break }
					if !tools.Digest_valid(cc.i.logs, id) { break }
					ok, RPCDATA := r.node.API("getrawtransaction", []string{id}); if !ok { break }
					ok, r.result = r.node.API("decoderawtransaction", []string{RPCDATA.(string)}); if !ok { break }
					r.success = true
			default:
					cc.i.logs<-"*CoinController: UNRECOGNISED API COMMAND "+r.action
		}
		if r.result == nil { r.success = false }
		if r.channel != nil { r.channel <- r }
	}
}

type Block struct {
	Hash string
	Confirmations float64
	Size float64
	Height int
	Version float64
	MerkleRoot string
	TX []string
	Time float64
	Nonce float64
	Bits string
	Difficulty float64
	PreviousBlockHash string
	NextBlockHash string
}

func (cc *CoinController) ImportBlocks(node *OBJ) {
	for x := cc.LatestBlock; x >= 0; x-- {
		block_num := tools.IntToString(x)
		file_path := cc.Paths["block"]+block_num+".blk"
		_, err := os.Stat(file_path)
		if err != nil {
			r := <- cc.CoinRequest(node, "getblock", x); if !r.success { tools.Quit_slow(cc.i.logs, "FAILED GETTING NEW BLOCK") }
			ok, encoded_block := tools.Encode_json(cc.i.logs, r.result); if !ok { tools.Quit_slow(cc.i.logs, "FAILED ENCODING NEW BLOCK") }
			if !tools.File_write_bytes(cc.i.logs, file_path, encoded_block) { tools.Quit_slow(cc.i.logs, "FAILED SAVING NEW BLOCK") }
			cc.ParseBlock(node, block_num, file_path)
		}
	}
}

func (cc *CoinController) LoadBlockchain() {

	cc.i.logs<-"**** LOADING BLOCKCHAIN "+cc.CoinName

	cc.Paths = make(map[string]string)
	cc.Paths["block"] = "BLK"
	cc.Paths["tx"] = "TX"
	cc.Paths["address"] = "ADR"
	
	for id, path := range cc.Paths { cc.Paths[id] = "./"+cc.CoinName+"/"+path+"/"; tools.File_makepath(cc.i.logs, cc.Paths[id]) }
	
	cc.ImportBlocks(cc.AnyNode())

}

func (cc *CoinController) ParseBlock(node *OBJ, blk_num, file_path string) {
		ok, block_bytes := tools.File_read_bytes(node.i.logs, file_path); if !ok { tools.Quit_slow(node.i.logs, "FAILED PARSING NEW BLOCK") }
		m := make(map[string]interface{})
		if !tools.Decode_json(node.i.logs, block_bytes, &m) { tools.Quit_slow(node.i.logs, "FAILED PARSING NEW BLOCK") }
		tx_list, ok := m["tx"].([]interface{}); if !ok { tools.Quit_slow(node.i.logs, "BLOCKPARSE: FAILED TX TYPE ASSERT SHOULD BE: "+reflect.TypeOf(m["tx"]).String()) }
		// send requests asynchronously
		txs := len(tx_list)
		tx_chan := make(chan bool, txs)
		wait, _ := time.ParseDuration("100ms")
		for i, id := range tx_list { go cc.ImportTX(node, tx_chan, blk_num, strconv.Itoa(i), id.(string)); time.Sleep(wait) }
		for finished := 0; finished < txs; finished++ { <- tx_chan }
		node.i.logs<-"PARSED BLOCK #"+blk_num+" WITH "+strconv.Itoa(txs)+" TX"
}

func (cc *CoinController) ImportTX(node *OBJ, tx_chan chan bool, block_num, tx_num, tx_id string) {
	for {
		tx_ref := block_num+":"+tx_num
		if !tools.Digest_valid(node.i.logs, tx_id) { break }
		_, err := os.Stat(cc.Paths["tx"]+tx_ref); if err == nil { break }
		ok, RPCDATA := node.API("getrawtransaction", []string{tx_id}); if !ok { break }
		ok, tx_bytes := node.RPC(map[string]interface{}{"jsonrpc":"2.0", "id":"1", "method":"decoderawtransaction", "params":[]interface{}{RPCDATA}}); if !ok { break }
		if !cc.ParseTransaction(tx_ref, tx_bytes) { tools.Quit_slow(cc.i.logs, "FAILED TO PARSE TRANSACTION") }
		tx_chan <- true
		return
	}
	tx_chan <- true
	node.i.logs<-"MISSING/FAILED TX IMPORT "+tx_id;
}

func (cc *CoinController) ParseTransaction(tx_ref string, tx_bytes []byte) bool {
	mm := make(map[string]interface{})
	if !tools.Decode_json(cc.i.logs, tx_bytes, &mm) { return false }
	ok, m := interface_to_map(cc.i.logs, mm["result"]); if !ok { return false }
	if !tools.File_write_bytes(cc.i.logs, cc.Paths["tx"]+tx_ref+".tx", tx_bytes) { return false }
	if m == nil || m["vout"] == nil { cc.i.logs<-"PARSETX: "+string(tx_bytes); return false }
	list, ok := m["vout"].([]interface{}); if !ok { cc.i.logs<-"PARSETX: VOUT ASSERTION FAIL: "+reflect.TypeOf(m["vout"]).String(); return false }
	for _, o := range list {
		ok, output := interface_to_map(cc.i.logs, o); if !ok { return false }
		value, ok := output["value"].(float64); if !ok { cc.i.logs<-"PARSETX: VALUE ASSERTION FAIL: "+reflect.TypeOf(output["value"]).String(); return false }
		str_value := tools.Format_float(value, 8)
		script_pub_key, ok := output["scriptPubKey"].(map[string]interface{}); if !ok { cc.i.logs<-"PARSETX: SCRIPTPUBKEY ASSERTION FAIL: "+reflect.TypeOf(output["scriptPubKey"]).String(); return false }
		if script_pub_key["addresses"] != nil {
			addresses, ok := script_pub_key["addresses"].([]interface{}); if !ok { cc.i.logs<-"PARSETX: ADDRESSES ASSERTION FAIL: "+reflect.TypeOf(script_pub_key["addresses"]).String(); return false }
			for _, a := range addresses {
				address, ok := a.(string); if !ok { cc.i.logs<-"PARSETX: ADDRESS ASSERTION FAIL: "+reflect.TypeOf(a).String(); return false }
				if !tools.File_makepath(cc.i.logs, cc.Paths["address"]+address) { return false }
				if !tools.File_write_string(cc.i.logs, cc.Paths["address"]+address+"/"+tx_ref+".in", str_value) { return false }
			}
		}
	}
	vin_list, ok := m["vin"].([]interface{}); if !ok { cc.i.logs<-"PARSETX: VIN ASSERTION FAIL: "+reflect.TypeOf(m["vin"]).String(); return false }
	for _, in := range vin_list {
		ok, input := interface_to_map(cc.i.logs, in); if !ok { return false }
		if input["coinbase"] != nil {
			if !tools.File_write_bytes(cc.i.logs, cc.Paths["tx"]+tx_ref+".coinbase", tx_bytes) { break }
		} else {
			if input["txid"] == nil || input["vout"] == nil { cc.i.logs<-"PARSETX: NIL TXID/VOUT "+string(tx_bytes); return false }
			txid, ok := input["txid"].(string); if !ok { cc.i.logs<-"PARSETX: VIN TXID ASSERTION FAIL: "+reflect.TypeOf(input["txid"]).String(); return false }
			vout, ok := input["vout"].(float64); if !ok { cc.i.logs<-"PARSETX: VIN VOUT ASSERTION FAIL: "+reflect.TypeOf(input["vout"]).String(); return false }
			input_path := cc.Paths["tx"]+txid+"/"
			tools.File_makepath(cc.i.logs, input_path)
			if !tools.File_write_string(cc.i.logs, input_path+strconv.Itoa(int(vout))+".out", tx_ref) { return false }
		}
	}
	return true
}


