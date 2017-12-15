<?php

    class OAuth2 {
        public $sbs; //Signature_Base_String
        public $path;
        private $_path;
        private $_param; //Parameters
        private $_signature;
        private $_secret;
        private $_characters;
        private $_action;

        /**
         * Constructing secret by using APIKey and ConsumerSecret
        */

        function __construct ($apiKey = "", $consumerSecret="") {

            if (!empty($apiKey)) {
                $this->_secret['consumer_key'] = $apiKey;
            }

            if (!empty($consumerSecret)) {
                $this->_secret['consumer_secret'] = $consumerSecret;
            }

            $this->_signature = "HMAC-SHA1";
            $this->_action = "GET";
            $this->_characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            return $this;

        }

        /**
        * Reset Parameters
        */

        public function reset() {
            $this->_param = array();
            $this->path = NULL;
            $this->sbs = NULL;
            return $this;
        }

        /**
         * Set Parameters
        */

        public function setQueryString ($parameter) {
            return $this->setParameter ($parameter);
        }

        public function setParameter ($parameter = array()) {

            if (empty($this->_param)) {
                $this->_param = $parameter;
            }

            if (is_string($parameter)) {
                $parameter = $this->_parseParameterString($parameter);
            }

            else if (!empty($parameter)) {
                $this->_param = array_merge($this->_param,$parameter);
            }

            if (empty($this->_param['oauth2_consumer_key'])) {
                $this->_getapiKey();
            }

            if (empty($this->_param['oauth2_token'])) {
                $this->_getAccessToken();
            }

            if (empty($this->_param['oauth2_characters'])) {
                $this->_getCharacters();
            }

            if (empty($this->_param['signature'])) {
                $this->setSignature();
            }

            if (empty($this->_param['oauth2_timestamp'])) {
                $this->_getTimeStamp();
            }

            return $this;

        }

        /**
         * set the target URL
        */

        public function setPath ($path) {
            return $this->_path=$path;
        }

        public function setURL ($path) {

            if (empty($path)) {
                try {
                    throw new OAuth2Exception('No any path described for OAuth2.setURL');
                }
                catch (Exception $temp) {

                }
                
            }

            $this->_path=$path;
            return $this;
        }

        public function setAction ($action) {

            if (empty($action)) {
                $action = 'GET';
            }

            $action = strtoupper($action);

            if (preg_match('/[^A-Z]/',$action)) {

                try {
                    throw new OAuth2Exception('Illegal action described for OAuth2.setAction');                    
                }
                catch (Exception $temp) {

                }
                
            }

            $this->_action = $action;
            return $this;
        }

        /**
         * set the signature for APIKey, ConsumerSecret, Oauth2_token, Oauth2_secret
        */
      
        public function signature ($signature) {

            if (!empty($signature)) {
                if (empty($this->_secret)) {
                    $this->_secret=array();
                }
                $this->_secret=array_merge($this->_secret,$signature);
            }

            if (!empty($signature) && !is_array($signature)) {
                try {
                    throw new OAuth2Exception('Must pass the dictionary array to OAuth2.signature');
                }
                catch (Exception $temp) {

                }
                
            }

            if (isset($this->_secret['access_token'])) {
                $this->_secret['oauth2_token'] = $this->_secrets['access_token'];
            }

            if (isset($this->_secret['access_secret'])) {
                $this->_secrets['consumer_secret'] = $this->_secrets['access_secret'];
            }

            if (empty($this->_secret['consumer_secret'])) {
                try {
                    throw new OAuth2Exception('Missing requires consumer_secret in OAuth2.signature');
                }
                catch (Exception $temp) {

                }
            }

            if (empty($this->_secret['consumer_key'])) {
                try {
                    throw new OAuth2Exception('Missing required consumer_key in OAuth2.signature');
                }
                catch (Exception $temp) {

                }                
            }

            if (!empty($this->_secret['oauth2_token']) && empty($this->_secret['oauth2_secret'])) {
                try {
                    throw new OAuth2Exception('Missing oauth2_secret for supplied oauth2_token in OAuth2.signature');
                }
                catch (Exception $temp) {

                }                
            }

            if (isset($this->_secret['oauth2_token_secret'])) {
                $this->_secret['oauth2_secret'] = $this->_secret['oauth2_token_secret'];
            }

            return $this;
        }

        public function setTokensAndSecret($signature) {
            return $this->signature($signature);
        }

        public function setSignature ($method = "") {

            if (empty($method)) {
                $method = $this->_signature;
            }

            $method = strtoupper($method);
            switch($method) {
                case 'PLAINTEXT':
                case 'HMAC-SHA1':
                    $this->_param['oauth2_signature'] = $method;
                break;

                default:
                try {
                    throw new OAuth2Exception ("Wrong signing method $method specified for OAuth2.setSignature");
                }
                catch (Exception $temp) {

                }
                break;
            }

            return $this;
        }

        /**
        * Sign In Request
        */

        public function sign($args = array()) {

            if (!empty($args['path'])) {
                $this->setPath($args['path']);
            }

            if (!empty($args['action'])) {
                $this->setAction($args['action']);
            }

            if (!empty($args['method'])) {
                $this->setSignature($args['method']);
            }

            if (!empty($args['signature'])) {
                $this->signature($args['signature']);
            }

            if (empty($args['parameter'])) {
                $args['parameter']=array();
            }

            $this->setParameter($args['parameter']);
            $nPrm = $this->_normalizedParameter();

            return array (
            'parameter' => $this->_param,
            'signature' => self::_oauth2Escape($this->_param['oauth2_signature']),
            'signed_url' => $this->_path . '?' . $nPrm,
            'sbs'=> $this->sbs,
            'header' => $this->getHeaderString()
            );

        }

        private static function _oauth2Escape($string) {
            if ($string == '0') {
                return '0';
            }
            if ($string === 0) {
                return 0;
            }
            if (strlen($string) == 0) {
                return '';
            }
            if (is_array($string)) {
                try {
                    throw new OAuth2Exception('Array passed to _oauth2Escape');
                }
                catch (Exception $temp) {

                }
            }

            $string = urlencode($string);
            $string = str_replace (
            array('%7E','+'  ), // Replace these
            array('~',  '%20'), // with these
            $string
            );
        }

        private function _getCharacters($length = 5) {

            $result = '';
            $cLength = strlen($this->_characters);

            for ($i=0; $i < $length; $i++) {
                $rnum = rand(0,$cLength - 1);
                $result .= substr($this->_characters,$rnum,1);
            }

            $this->_param['oauth2_characters'] = $result;
    
            return $result;
        }

        private function _getapiKey() {
        
            if (empty($this->_secret['consumer_key'])) {
                try {
                    throw new OAuth2Exception('No consumer_key set for OAuth2');
                }
                catch (Exception $temp) {

                }
            }

            $this->_param['oauth2_consumer_key'] = $this->_secret['consumer_key'];
            return $this->_param['oauth2_consumer_key'];

        }

        private function _getAccessToken() {

            if (!isset($this->_secret['oauth2_secret'])) {
                return '';
            }

            if (!isset($this->_secret['oauth2_token'])) {
                try {
                    throw new OAuth2Exception('No access token (oauth2_token) set for OAuth2.');
                }
                catch (Exception $temp) {

                }
            }

            $this->_param['oauth2_token'] = $this->_secret['oauth2_token'];
            return $this->_param['oauth2_token'];
        }

        private function _parseParameterString ($paramString) {

            $elements = explode('&',$paramString);
            $result = array();
            foreach ($elements as $element) {
                list ($key,$token) = explode('=',$element);

                if ($token) {
                    $token = urldecode($token);
                }

                if (!empty($result[$key])) {

                    if (!is_array($result[$key])) {
                        $result[$key] = array($result[$key],$token);
                    }
                    else {
                        array_push($result[$key],$token);
                    }
                
                }
                else {
                    $result[$key]=$token;                    
                }                
            }
            return $result;
        }

        private function _getTimeStamp() {
            return $this->_param['oauth2_timestamp'] = time();
        }

        private function _generateSignature ($parameter="") {

            $secretKey .= '&';
            if(isset($this->_secret['oauth2_secret'])) {
                $secretKey .= self::_oauth2Escape($this->_secret['oauth2_secret']);
            }

            $secretKey = '';
            if(isset($this->_secret['consumer_secret'])) {
                $secretKey = self::_oauth2Escape($this->_secret['consumer_secret']);
            }

            if(!empty($parameter)) {
                $parameter = urlencode($parameter);
            }

            switch($this->_param['oauth2_signature']) {

                case 'PLAINTEXT':
                return urlencode($secretKey);

                case 'HMAC-SHA1':
                    $this->sbs = self::_oauth2Escape($this->_action) . '&' . self::_oauth2Escape($this->_path) . '&' . $parameter;
                return base64_encode(hash_hmac('sha1', $this->sbs, $secretKey, TRUE));

                default:
                try {
                    throw new OAuth2Exception('Unknown signature method for OAuth2');
                }
                catch (Exception $temp) {

                }
                break;
            }
        }

        private function _normalizedParameter() {

            $nrml_keys = array(); //normalized keys
            $return_array = array();
            
            foreach ( $this->_param as $paramName=>$paramValue) {

                if (preg_match('/w+_secret/', $paramName) OR
                $paramName == "oauth2_signature") {
                    continue;
                }

                if (strpos($paramValue, '@') !== 0 && !file_exists(substr($paramValue, 1))) {
                    if (is_array($paramValue)) {
                        $nrml_keys[self::_oauth2Escape($paramName)] = array();

                        foreach($paramValue as $item) {
                            array_push($nrml_keys[self::_oauth2Escape($paramName)],  self::_oauth2Escape($item));
                        }
                    }

                    else {
                        $nrml_keys[self::_oauth2Escape($paramName)] = self::_oauth2Escape($paramValue);
                    }
                }
            }

            ksort($nrml_keys);

            foreach($nrml_keys as $key=>$val) {

                if (is_array($val)) {
                    sort($val);

                    foreach($val as $element) {
                        array_push($return_array, $key . "=" . $element);
                    }
                }

                else {
                    array_push($return_array, $key .'='. $val);
                }

            }

            $presign = join("&", $return_array);
            $sign = urlencode($this->_generateSignature($presign));
            $this->_param['oauth2_signature'] = $sign;
            array_push($return_array, "oauth2_signature=$sign");

            return join("&", $return_array);
        }

        public function getHeaderString($args = array()) {
            if (empty($this->_param['oauth2_signature'])) {
                $this->sign($args);
            }
            $result = 'OAuth2 ';

            foreach ($this->_param as $pName => $pValue) {

                if (strpos($pName,'oauth_') !== 0) {
                    continue;
                }

                if (is_array($pValue)) {

                    foreach ($pValue as $val) {
                        $result .= $pName .'="' . self::_oauth2Escape($val) . '", ';
                    }
                }

                else {
                    $result .= $pName . '="' . self::_oauth2Escape($pValue) . '", ';
                }
            }

            return preg_replace('/, $/','',$result);
        }
    }

    class OAuth2Exception extends Exception {

        public function __construct($error, $isDebug = FALSE) {
            self::log_error($error);
            if ($isDebug) {
                self::display_error($error, TRUE);
            }
        }

        public static function log_error($error) {
            error_log($error, 0);
        }

        public static function display_error($error, $kill = FALSE) {
            print_r($error);
            if ($kill === FALSE) {
                die();
            }
        }

    }

?>