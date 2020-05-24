(ns buddy.sign.jwk-cache
  (:require [cheshire.core :as json]
            [byte-streams :as streams]
            [aleph.http :as http]
            [buddy.core.keys :as keys]))

(def ^:private jwk-cache (atom {}))
(def ^:private refresh-delay-ms 10000)

(defn- fetch
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

(defn- allow-cache-refresh?
  [well-known-endpoint]
  (> (- (System/currentTimeMillis)
        (get-in @jwk-cache [well-known-endpoint :last-refresh-ms] -1))
     refresh-delay-ms))

(defn- fetch-jwk
  [well-known-endpoint kid]
  (if-let [jwk (get-in @jwk-cache [well-known-endpoint :keys kid])]
    jwk
    (when (allow-cache-refresh? well-known-endpoint)
      (refresh-jwk-cache well-known-endpoint)
      (get-in @jwk-cache [well-known-endpoint :keys kid]))))

(defn get-public-key
  [well-known-endpoint kid]
  (when-let [jwk (fetch-jwk well-known-endpoint kid)]
    (keys/jwk->public-key jwk)))

