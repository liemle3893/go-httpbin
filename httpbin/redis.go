/**
 * Created by liemlhd on 05/Dec/2022
 */

package httpbin

import (
	"encoding/json"
	"errors"
	"github.com/go-redis/redis/extra/redisotel/v9"
	"github.com/go-redis/redis/v9"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"net/http"
	"strings"
)

func init() {
	redisotel.WithTracerProvider(otel.GetTracerProvider())
	redisotel.WithDBStatement(true)
	redisotel.WithDBSystem("redis")
}

func (h *HTTPBin) handleRedisCall(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("myapp.redis").Start(r.Context(), "myapp.http_redis")
	defer span.End()
	redisURI := r.URL.Query().Get("uri")
	rdb := redis.NewClient(&redis.Options{
		Addr: redisURI,
	})
	defer rdb.Close()
	if err := redisotel.InstrumentTracing(rdb); err != nil {
		panic(err)
	}
	if err := redisotel.InstrumentMetrics(rdb); err != nil {
		panic(err)
	}
	redisCommand := r.URL.Query().Get("command")
	params := strings.Split(r.URL.Query().Get("params"), ",")
	var (
		val interface{}
		err error
	)
	switch redisCommand {
	case "get":
		val, err = rdb.Get(ctx, params[0]).Result()
	case "set":
		val, err = rdb.Set(ctx, params[0], params[1], 0).Result()
	}
	if err != nil {
		if errors.Is(err, redis.Nil) {
			span.SetStatus(codes.Error, "key not found")
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("key not found"))
			return
		}
		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)
		return
	}
	bytes, err := json.Marshal(val)
	if err != nil {
		span.RecordError(err)
		return
	}
	_, _ = w.Write(bytes)
}

//func InterfaceSlice(slice interface{}) []interface{} {
//	s := reflect.ValueOf(slice)
//	if s.Kind() != reflect.Slice {
//		return nil
//	}
//	// Keep the distinction between nil and empty slice input
//	if s.IsNil() {
//		return nil
//	}
//	ret := make([]interface{}, s.Len())
//
//	for i := 0; i < s.Len(); i++ {
//		ret[i] = s.Index(i).Interface()
//	}
//	return ret
//}
