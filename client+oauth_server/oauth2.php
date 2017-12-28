<?php

ini_set("allow_url_fopen", 1);

    class OAuth2 {
    
        public $path;
        private $_path;
        private $_param; //Parameters
        private $_secret;
        private $_characters;
        private $_action;

        /**
         * Constructing secret by using APIKey and ConsumerSecret
         * This value of consumer_key and consumer_secret is usually provided by the site you wish to use.
        */

        function __construct ($apiKey = "", $consumerSecret="") {

            if (!empty($apiKey)) {
                $this->_secret['consumer_key'] = $apiKey;
            }

            if (!empty($consumerSecret)) {
                $this->_secret['consumer_secret'] = $consumerSecret;
            }

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
            return $this;
        }

        /**
         * Set Parameters
         * 
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
        * Sign In Request
        */

        public function sign($args = array()) {

            if (!empty($args['path'])) {
                $this->setPath($args['path']);
            }

            if (!empty($args['action'])) {
                $this->setAction($args['action']);
            }


            if (empty($args['parameter'])) {
                $args['parameter']=array();
            }

            $this->setParameter($args['parameter']);
            $nPrm = $this->_normalizedParameter();

            return array (
            'parameter' => $this->_param,
            'signed_url' => $this->_path . '?' . $nPrm,
            'header' => $this->getHeaderString()
            );

        }

        private static function _oauth2Escape($string) {
            if ($string === 0) {                
                return 0;
            }
            if ($string == '0') { 
                return '0'; 
            }
            if (strlen($string) == 0) { 
                return ''; 
            }
            if (is_array($string)) {
                try {
                    throw new OAuth2Exception('Array passed to _oauth2Escape');
                }
            catch (Exception $temp) {}
            }
            $string = urlencode($string);
    
            //FIX: urlencode of ~ and '+'
            $string = str_replace(
                array('%7E','+'  ), // Replace these 
                array('~',  '%20'), // with these
                $string);
    
            return $string;
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


        private function _normalizedParameter() {

            $nrml_keys = array(); //normalized keys
            $return_array = array();
            
            foreach ( $this->_param as $paramName=>$paramValue) {

                if (preg_match('/w+_secret/', $paramName)) {
                    continue;
                }

                /**
                 * Read parameters from a file.
                 * In php.ini file set
                 * Uncommenting : extension=php_openssl.dll
                 * Switch on : allow_url_include = On
                */
              
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

            ksort($nrml_keys); // To sort an associative array in ascending order, according to the key

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

            return join("&", $return_array);
        }

        public function getHeaderString($args = array()) {
        
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
