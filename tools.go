package synchro

import (
		"reflect"
		)
		
func interface_to_map(logs chan string, x interface{}) (bool, map[string]interface{}) {
	y, ok := x.(map[string]interface{})
	if ok { return true, y }
	logs<-"TOOLS/I2MAP: FAILED TYPE ASSERTION, SHOULD BE "+reflect.TypeOf(x).String()
	return false, nil
}

func (i *Infrastructure) ReadGlobal(key string) string {
	i.RLock()
	defer i.RUnlock()
	return i.GLOBALS[key]
}

func (i *Infrastructure) SetGlobal(key, value string) {
	i.Lock()
		i.GLOBALS[key] = value
	i.Unlock()
}