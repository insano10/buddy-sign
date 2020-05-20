(ns buddy.sign.jwk-cache-tests
  (:require [clojure.test :refer :all]
            [buddy.core.keys :as keys]
            [buddy.sign.jwk :as jwk]))

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

(deftest fetch-known-key-from-jwk-cache
  (with-redefs [jwk/fetch (fn [_] full-jwk-doc)]
    (is (= (jwk/get-public-key "http://well-known-endpoint" "LYyP2g")
           (keys/str->public-key (:LYyP2g public-keys))))))

(deftest fetch-unknown-key-from-jwk-cache
  (with-redefs [jwk/fetch (fn [_] full-jwk-doc)]
    (is (nil? (jwk/get-public-key "http://well-known-endpoint" "unknown")))))

(deftest fetch-newly-rotated-known-key-from-jwk-cache
  (testing "cache starts empty and keys are retrieved"
    (with-redefs [jwk/fetch (fn [_] {:keys [LYyP2g-key,
                                            mpf0DA-key]})]
      (is (= (jwk/get-public-key "http://well-known-endpoint" "LYyP2g")
             (keys/str->public-key (:LYyP2g public-keys))))))

  (testing "request for key not in cache causes it to be refreshed from the wke"
    (with-redefs [jwk/fetch (fn [_] {:keys [mpf0DA-key,
                                            b9vTLA-key]})]
      (is (= (jwk/get-public-key "http://well-known-endpoint" "b9vTLA")
             (keys/str->public-key (:b9vTLA public-keys)))))))

