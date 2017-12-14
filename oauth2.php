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
    }

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

    public function reset() {
        $this->_parameter = array();
        $this->path = NULL;
        $this->sbs = NULL;
        return $this;
    }

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

    public function setTokensAndSecret($signature) {
        return $this->signature($signature);
    }

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

    /**
     * Sign In Request
     */

    public function sign($args = array()) {

        if (!empty($args['path'])) {
            this->setPath($args['path']);
        }

        if (!empty($args['action'])) {
            this->setAction($action['action']);
        }

        if (!empty($args['method'])) {
            this->setSignature($method['method']);
        }

        if (!empty($args['signature'])) {
            $this->signature($args['signature']);
        }

        if (empty($args['parameter'])) {
            $args['parameter']=array();
        }

        $this->setParameter($args['parameter']);
        $nPrm = $this->_normalisedParameter();

    }


?>
