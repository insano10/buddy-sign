(ns buddy.sign.jwk-cache
  (:require [cheshire.core :as json]
            [byte-streams :as streams]
            [aleph.http :as http]
            [buddy.core.keys :as keys]))

(def ^:private jwk-cache (atom {}))

(defn- string->edn
  "Parse JSON from a string returning an edn map, otherwise nil"
  [string]
  (when-let [edn (json/decode string true)]
    (when (map? edn)
      edn)))

(defn- fetch
  "Obtain HTTP resource and parse it into a Clojure map"
  [endpoint]
  (-> @(http/get endpoint)
      :body
      streams/to-string                                     ;todo do i really need byte-streams for this
      string->edn))

(defn- refresh-jwk-cache
  [well-known-endpoint]
  (when-let [jwk-doc (:keys (fetch well-known-endpoint))]
    (reset! jwk-cache (zipmap (map :kid jwk-doc) jwk-doc))))

(defn- fetch-jwk
  [well-known-endpoint kid]
  (if-let [jwk (get @jwk-cache kid)]
    jwk
    (do
      (refresh-jwk-cache well-known-endpoint)
      (get @jwk-cache kid))))

(defn get-public-key
  "Obtain the JWK public key from the well-known endpoint that matches the kid"
  [well-known-endpoint kid]
  (when-let [jwk (fetch-jwk well-known-endpoint kid)]
    (keys/jwk->public-key jwk)))

