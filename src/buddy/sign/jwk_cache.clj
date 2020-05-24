(ns buddy.sign.jwk-cache
  (:require [cheshire.core :as json]
            [byte-streams :as streams]
            [aleph.http :as http]
            [buddy.core.keys :as keys]))

(def ^:private jwk-cache (atom {}))

(defn- fetch
  "Obtain HTTP resource and parse it into a Clojure map"
  [endpoint]
  (-> @(http/get endpoint)
      :body
      streams/to-string
      (json/parse-string true)))

(defn- refresh-jwk-cache
  [well-known-endpoint]
  (when-let [jwk-doc (:keys (fetch well-known-endpoint))]
    (swap! jwk-cache (fn [cache] (assoc cache
                                   well-known-endpoint
                                   {:last-refresh-ms (System/currentTimeMillis)
                                    :keys            (zipmap (map :kid jwk-doc) jwk-doc)})))))

(defn- last-cache-refresh-more-than-10-secs-ago
  [well-known-endpoint]
  (> (- (System/currentTimeMillis)
        (get-in @jwk-cache [well-known-endpoint :last-refresh-ms] 0))
     10000))

(defn- fetch-jwk
  [well-known-endpoint kid]
  (if-let [jwk (get-in @jwk-cache [well-known-endpoint :keys kid])]
    jwk
    (when (last-cache-refresh-more-than-10-secs-ago well-known-endpoint)
      (refresh-jwk-cache well-known-endpoint)
      (get-in @jwk-cache [well-known-endpoint :keys kid]))))

(defn get-public-key
  "Obtain the JWK public key from the well-known endpoint that matches the kid"
  [well-known-endpoint kid]
  (when-let [jwk (fetch-jwk well-known-endpoint kid)]
    (keys/jwk->public-key jwk)))

