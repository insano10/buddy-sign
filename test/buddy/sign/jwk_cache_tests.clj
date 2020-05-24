(ns buddy.sign.jwk-cache-tests
  (:require [clojure.test :refer :all]
            [buddy.core.keys :as keys]
            [buddy.sign.jwk-cache :as jwk])
  (:import (java.util UUID)))

(def public-keys {:LYyP2g "-----BEGIN PUBLIC KEY-----\n
                           MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESlXFFkJ3JxMsXyXNrqzE3ozl/091 3PmNbccLLWfeQFUYtJqGtl8ESuYxRwc/QwZp5Wcl0HCq6GuFDx4/Tk18Ig==\n
                           -----END PUBLIC KEY-----",
                  :b9vTLA "-----BEGIN PUBLIC KEY-----\n
                           MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqCByTAvci+jRAD7uQSEhTdOs8iA7 14IbcY2L++YzynJZBjS4KhDI9KjNYoZDRqeYV44fkk1eJlr2LpI2o5ybvA==\n
                           -----END PUBLIC KEY----- ",
                  :mpf0DA "-----BEGIN PUBLIC KEY-----\n
                           MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfHEdeT3a6KaC1kbwov73ZwB/SiUH EyKQwUUtMCEn0aJBY6PA+Eic24+WqPEtDKG95elao4VxA+Fne36Sgw1tkg==\n
                           -----END PUBLIC KEY----- "})

(def LYyP2g-key {:alg "ES256",
                 :crv "P-256",
                 :kid "LYyP2g",
                 :kty "EC",
                 :use "sig",
                 :x   "SlXFFkJ3JxMsXyXNrqzE3ozl_0913PmNbccLLWfeQFU",
                 :y   "GLSahrZfBErmMUcHP0MGaeVnJdBwquhrhQ8eP05NfCI"})
(def mpf0DA-key {:alg "ES256",
                 :crv "P-256",
                 :kid "mpf0DA",
                 :kty "EC",
                 :use "sig",
                 :x   "fHEdeT3a6KaC1kbwov73ZwB_SiUHEyKQwUUtMCEn0aI",
                 :y   "QWOjwPhInNuPlqjxLQyhveXpWqOFcQPhZ3t-koMNbZI"})
(def b9vTLA-key {:alg "ES256",
                 :crv "P-256",
                 :kid "b9vTLA",
                 :kty "EC",
                 :use "sig",
                 :x   "qCByTAvci-jRAD7uQSEhTdOs8iA714IbcY2L--YzynI",
                 :y   "WQY0uCoQyPSozWKGQ0anmFeOH5JNXiZa9i6SNqOcm7w"})
(def full-jwk-doc {:keys [LYyP2g-key,
                          mpf0DA-key,
                          b9vTLA-key]})

(defn- wke-url [] (str "http://wke-" (UUID/randomUUID)))

(use-fixtures :once (fn [f] (with-redefs [jwk/refresh-delay-ms 0] f)))

(deftest fetch-known-key-from-jwk-cache
  (with-redefs [jwk/fetch (fn [_] full-jwk-doc)]
    (is (= (jwk/get-public-key (wke-url) "LYyP2g")
           (keys/str->public-key (:LYyP2g public-keys))))))

(deftest fetch-unknown-key-from-jwk-cache
  (with-redefs [jwk/fetch (fn [_] full-jwk-doc)]
    (is (nil? (jwk/get-public-key (wke-url) "unknown")))))

(deftest fetch-newly-rotated-known-key-from-jwk-cache
  (let [wke (wke-url)]
    (testing "cache starts empty and keys are retrieved"
      (with-redefs [jwk/fetch (fn [_] {:keys [LYyP2g-key,
                                              mpf0DA-key]})]
        (is (= (jwk/get-public-key wke "LYyP2g")
               (keys/str->public-key (:LYyP2g public-keys))))))

    (testing "request for key not in cache causes it to be refreshed from the wke"
      (with-redefs [jwk/fetch (fn [_] {:keys [mpf0DA-key,
                                              b9vTLA-key]})]
        (is (= (jwk/get-public-key wke "b9vTLA")
               (keys/str->public-key (:b9vTLA public-keys))))))))

(deftest cache-is-not-refreshed-if-it-was-already-refreshed-in-the-last-10-secs
  (let [wke (wke-url)]
    (testing "cache starts empty and keys are retrieved"
      (with-redefs [jwk/fetch (fn [_] {:keys [LYyP2g-key]})]
        (is (= (jwk/get-public-key wke "LYyP2g")
               (keys/str->public-key (:LYyP2g public-keys))))))

    (testing "immediate cache miss again does not trigger refresh"
      (with-redefs [jwk/refresh-delay-ms 10000
                    jwk/fetch (fn [_] {:keys [b9vTLA-key]})]
        (is (nil? (jwk/get-public-key wke "b9vTLA")))))))

(deftest different-wkes-are-cached-separately
  (testing "key is retrieved for wke"
    (with-redefs [jwk/fetch (fn [_] {:keys [LYyP2g-key]})]
      (is (= (jwk/get-public-key (wke-url) "LYyP2g")
             (keys/str->public-key (:LYyP2g public-keys))))))

  (testing "key is not present for different wke"
    (with-redefs [jwk/fetch (fn [_] nil)]
      (is (nil? (jwk/get-public-key (wke-url) "LYyP2g"))))))

