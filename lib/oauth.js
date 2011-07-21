var crypto      = require('crypto'),
    //sha1        = require('./sha1'),
    http        = require('http'),
    https       = require('https'),
    url         = require('url'),
    util        = require('util'),
    querystring = require('querystring'),
    _           = require("underscore"),
    
// OAuth constructor
OAuth = function( options ) {

    this.requestUrl         = options.requestUrl;
    this.accessUrl          = options.accessUrl;
    this.consumerKey        = options.consumerKey;
    this.consumerSecret     = options.consumerSecret;
    this.version            = options.version;
    this.authorizeCallback  = options.authorizeCallback;
    this.signatureMethod    = options.signatureMethod || "HMAC-SHA1";
    this.headers            = options.customHeaders || {
        "Accept"        : "*/*",
        "Connection"    : "close",
        "User-Agent"    : "Node authentication"
    }

};

// Static methods
_.extend( OAuth, {

    getTimestamp : function() {
        return ( +new Date ) / 1000 | 0;
    },

    //  From http://tools.ietf.org/html/rfc5849#section-3.6
    //
    //  *   Characters in the unreserved character set as defined by
    //      [RFC3986], Section 2.3 (ALPHA, DIGIT, "-", ".", "_", "~") MUST
    //      NOT be encoded.
    //
    //  *   All other characters MUST be encoded.
    //
    //  *   The two hexadecimal characters used to represent encoded
    //      characters MUST be uppercase.
    percentEncode : (function() {
        
        var unreserved = /[^A-Za-z0-9-\._~]/g;

        return function( str ) {
            return ("" + str).replace( unreserved, function( char ) {
                return "%" + char.charCodeAt(0).toString(16).toUpperCase();
            })
        }
    }()),

    percentDecode: (function() {
        
        var percent = /%([A-Z0-9]){2}/g;
        return function percentDecode( str ) {
            if ( percent.test( str )) {
                return percentDecode( str.replace( percent, function( code ) {
                    return String.fromCharCode( + ("0x" + code.replace("%", "") ));
                }));
            } else {
                return str;
            }
        }

    }()),

    getNonce : function() {
       return Math.random().toString(36).slice(2);
    },

    normalizeUri : function( uri ) {

        var parts = uri.split("/");

        return parts.concat( parts.splice(3).map(function( value ) {
            return encodeURIComponent( value ); 
        })).join("/")
    },

    getBoundary : function( body ) {
        return body.match( /--(.+)(?:--)?(?:\n|\r|\r\n)?/ ).pop();
    }

});

// Instance methods
_.extend( OAuth.prototype, {

    _getParameters : function( params, token, nonce, timestamp ) {
        
        // Get an object containing all the parameters
        var allParams   = _.extend( params || {}, {
                oauth_consumer_key       : this.consumerKey,
                oauth_token              : token,
                oauth_nonce              : nonce,
                oauth_timestamp          : timestamp,
                oauth_signature_method   : this.signatureMethod,
                oauth_version            : this.version
            });

        // Join key pairs, sort, join params
        return _.map( allParams, function( value, key ) {
            return [
                key, 
                OAuth.percentEncode( value ) 
            ].join("=");
        }).sort().join("&");

    },

    _createBaseString : function( httpMethod, uri, params ) {
        return [
            httpMethod,
            OAuth.percentEncode( uri ),
            OAuth.percentEncode( params )
        ].join("&"); 
    },

    _createKey : function( tokenSecret ) {
        return [
            this.consumerSecret, 
            tokenSecret || "" 
        ].join("&");
    },

    _getAuthorizationHeader : function( token, signature, timestamp, nonce, params ) {

        var oauthParams = _.extend({
            oauth_consumer_key : this.consumerKey,
            oauth_token : token,
            oauth_signature_method : this.signatureMethod,
            oauth_signature : signature,
            oauth_timestamp : timestamp,
            oauth_nonce : nonce,
            oauth_version : this.version
        }, params );

        return "OAuth " + _.map( oauthParams, function( value, key ) {
            return  [ key, '"' + value + '"' ].join("="); 
        }).sort().join(", ");

    },

    request : function( httpMethod, uri, paramObj, credentials, options, callback ) {

        // Normalize arguments
        if ( _.isFunction( options )) {
            callback = options;
            options = {};
        }

        httpMethod = httpMethod.toUpperCase();
        uri = OAuth.normalizeUri( uri );

        var nonce       = OAuth.getNonce(),
            timestamp   = OAuth.getTimestamp(),
            parameters  = this._getParameters( paramObj, credentials.token, nonce, timestamp ),
            baseString  = this._createBaseString( httpMethod,  uri, parameters ),
            key         = this._createKey( credentials.tokenSecret ),
            signature   = OAuth.percentEncode( crypto.createHmac( "sha1", key ).update( baseString ).digest("base64") ),
            uriParts    = url.parse( uri ),
            isSecureUri = uriParts.protocol === "https:",
            boundary    = options.body && OAuth.getBoundary( options.body ),
            requestObj  = {
                host: uriParts.hostname,
                port: ( isSecureUri ? 443 : 80 ),
                path: [
                    uri.split( uriParts.hostname ).pop(), 
                    parameters
                ].join("?"),
                method: httpMethod,
                headers: _.extend({
                    "Authorization"     : this._getAuthorizationHeader( credentials.token, signature, timestamp, nonce ),
                    "Host"              : uriParts.hostname,
                    "Content-Length"    : options.body ? Buffer.byteLength( options.body ) : 0,
                    "Content-Type"      : options.body ? "multipart/form-data; boundary=" + boundary : "application/x-www-form-urlencoded"
                }, this.headers )
            },
            request;

        // Create request
        request     = ( isSecureUri ? https : http ).request( requestObj );


        request.on('response', function ( response ) {

            var data;
            
            // If there's no callback, we dont have to do this stuff
            if ( callback ) {

                // This will hold the data chunks
                data = [];

                // UTF-8 FTW
                response.setEncoding('utf8');


                response.on('data', function ( chunk ) {
                    data.push( chunk );
                });
                response.on('end', function () {
                    data = data.join("");
                    if ( response.statusCode != 200 ) {
                        if ( response.statusCode == 403 ) {
                            console.log( "Used:     " + baseString);
                            console.log( "Expected: " + JSON.parse( data ).error.split(": ").pop() );
                        }
                        callback({
                            statusCode: response.statusCode,
                            data: data
                        });
                    } else {
                        callback(null, data, response);
                    }
                });
            }
        });

        request.on("error", function( error ) {
            callback( error );
        });

        // Write out the post or put body
        if ( options.body && /^(?:PUT|POST)$/.test( httpMethod ) ) {
            request.write( options.body, options.requestEncoding || "binary" );
        }

        // Finish request
        request.end();
    }

});

module.exports = OAuth;