<?php

    class OAuth2 {
        public $sbs;
        public $path;
        private $_path;
        private $_parameter;
        private $_signature;
        private $_secret;
        private $_character;
        private $_action;

        /**
         * Constructing secret by using APIKey and ConsumerSecret
        */

        function __construct ($APIKey = "", $consumerSecret="") {

            if (!empty($APIKey)) {
                $this->_secret['consumer_key'] = $APIKey;
            }

            if (!empty($consumerSecret)) {
                $this->_secret['consumer_secret'] = $consumerSecret;
            }

            $this->_signature = "HMAC-SHA1";
            $this->_action = "GET";
            $this->_character = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            return $this;

        }

        /**
        * Reset Parameters
        */

        public function reset() {
            $this->_parameter = array();
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

            if (empty($this->_parameter)) {
                $this->_parameter = $parameter;
            }

            if (is_string($parameter)) {
                $parameter = $this->_parseParameterString($parameter);
            }

            else if (!empty($parameter)) {
                $this->_parameter = array_merge($this->_parameter,$parameter);
            }

            if (empty($this->_parameter['oauth2_consumer_key'])) {
                $this->_getApiKey();
            }

            if (empty($this->_parameter['oauth2_token'])) {
                $this->_getAccessToken();
            }

            if (empty($this->_parameter['oauth2_character'])) {
                $this->_getCharacter();
            }

            if (empty($this->_parameter['signature'])) {
                $this->setSignature();
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
                throw new OAuth2Exception('No any path described for OAuth2.setURL');
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
                throw new OAuth2Exception('Illegal action described for OAuth2.setAction');
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
                throw new OAuth2Exception('Must pass the dictionary array to OAuth2.signature');
            }

            if (isset($this->_secret['access_token'])) {
                $this->_secret['oauth2_token'] = $this->_secrets['access_token'];
            }

            if (isset($this->_secret['access_secret'])) {
                $this->_secrets['consumer_secret'] = $this->_secrets['access_secret'];
            }

            if (empty($this->_secret['consumer_secret'])) {
                throw new OAuth2Exception('Missing requires consumer_secret in OAuth2.signature');
            }

            if (empty($this->_secret['consumer_key'])) {
                throw new OAuth2Exception('Missing required consumer_key in OAuth2.signature');
            }

            if (!empty($this->_secret['oauth2_token']) && empty($this->_secret['oauth2_secret'])) {
                throw new OAuth2Exception('Missing oauth2_secret for supplied oauth2_token in OAuth2.signature');
            }

            return $this;
        }

        public function setTokensAndSecret($signature) {
            return $this->signature($signature);
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
            $nPrm = $this->_normalisedParameter();

            return array (
            'parameter' => $this->_parameter,
            'signature' => self::_oauth2Escape($this->_parameter['oauth2_signature']),
            'signed_url' => $this->_path . '?' . $nPrm,
            'sbs'=> $this->sbs
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
                throw new OAuth2Exception('Array passed to _oauth2Escape');
            }

            $string = urlencode($string);
            $string = str_replace (
            array('%7E','+'  ), // Replace these
            array('~',  '%20'), // with these
            $string
            );
        }

        private function _getApiKey() {
        
            if (empty($this->_secret['consumer_key'])) {
                throw new OAuth2Exception('No consumer_key set for OAuth2');
            }

            $this->_parameter['oauth2_consumer_key'] = $this->_secret['consumer_key'];
            return $this->_parameter['oauth2_consumer_key'];

        }

        private function _getAccessToken() {

            if (!isset($this->_secret['oauth2_secret'])) {
                return '';
            }

            if (!isset($this->_secret['oauth2_token'])) {
                throw new OAuth2Exception('No access token (oauth2_token) set for OAuth2.');
            }

            $this->_parameter['oauth2_token'] = $this->_secret['oauth2_token'];
            return $this->_parameter['oauth2_token'];
        }

    }

?>
