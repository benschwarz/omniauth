require 'omniauth/oauth'
require 'multi_json'

module OmniAuth
  module Strategies
    # 
    # Authenticate to Google via OAuth and retrieve basic
    # user information.
    #
    # Usage:
    #
    #    use OmniAuth::Strategies::Google, 'consumerkey', 'consumersecret'
    #
    class Google < OmniAuth::Strategies::OAuth
      SCOPES = {
        :analytics        => "https://www.google.com/analytics/feeds/",
        :base             => "https://www.google.com/base/feeds/",
        :buzz             => "https://www.googleapis.com/auth/buzz",
        :book_search      => "https://www.google.com/books/feeds/",
        :blogger          => "https://www.blogger.com/feeds/",
        :calendar         => "https://www.google.com/calendar/feeds/",
        :contacts         => "http://www.google.com/m8/feeds",
        :chrome_web_store => "https://www.googleapis.com/auth/chromewebstore.readonly",
        :docs             => "https://docs.google.com/feeds/",
        :finance          => "https://finance.google.com/finance/feeds/",
        :gmail            => "https://mail.google.com/mail/feed/atom",
        :health           => "https://www.google.com/health/feeds/",
        :h9               => "https://www.google.com/h9/feeds/",
        :maps             => "https://maps.google.com/maps/feeds/",
        :moderator        => "https://www.googleapis.com/auth/moderator",
        :opensocial       => "https://www-opensocial.googleusercontent.com/api/people/",
        :orkut            => "https://orkut.gmodules.com/social/rest",
        :picasa           => "https://picasaweb.google.com/data/",
        :sidewiki         => "https://www.google.com/sidewiki/feeds/",
        :sites            => "https://sites.google.com/feeds/",
        :spreadsheets     => "https://spreadsheets.google.com/feeds/",
        :url_shortener    => "https://www.googleapis.com/auth/urlshortener",
        :wave             => "http://wave.googleusercontent.com/api/rpc",
        :webmaster_tools  => "https://www.google.com/webmasters/tools/feeds/",
        :youtube          => "https://gdata.youtube.com",
        :reader           => "https://www.google.com/reader/api/"
      }
      
      def initialize(app, consumer_key = nil, consumer_secret = nil, options = {}, &block)
        client_options = {
          :site => 'https://www.google.com',
          :request_token_path => '/accounts/OAuthGetRequestToken',
          :access_token_path => '/accounts/OAuthGetAccessToken',
          :authorize_path => '/accounts/OAuthAuthorizeToken'
        }
        
        options[:scope] = :contacts unless options.key? :scope

        super(app, :google, consumer_key, consumer_secret, client_options, options)
      end
      
      def auth_hash
        ui = user_info
        OmniAuth::Utils.deep_merge(super, {
          'uid' => ui['uid'],
          'user_info' => ui,
          'extra' => {'user_hash' => user_hash}
        })
      end
      
      def user_info
        email = user_hash['feed']['id']['$t']
        
        name = user_hash['feed']['author'].first['name']['$t']
        name = email if name.strip == '(unknown)'
        
        {
          'email' => email,
          'uid' => email,
          'name' => name
        }
      end
      
      def user_hash
        # Google is very strict about keeping authorization and
        # authentication separated.
        # They give no endpoint to get a user's profile directly that I can
        # find. We *can* get their name and email out of the contacts feed,
        # however. It will fail in the extremely rare case of a user who has
        # a Google Account but has never even signed up for Gmail. This has
        # not been seen in the field.
        @user_hash ||= MultiJson.decode(@access_token.get("http://www.google.com/m8/feeds/contacts/default/full?max-results=1&alt=json").body)
      end

      # Monkeypatch OmniAuth to pass the scope in the consumer.get_request_token call
      def request_phase
        request_token = consumer.get_request_token({:oauth_callback => callback_url}, {:scope => SCOPE[options[:scope]]})

        (session['oauth']||={})[name.to_s] = {'callback_confirmed' => request_token.callback_confirmed?, 'request_token' => request_token.token, 'request_secret' => request_token.secret}
        r = Rack::Response.new

        if request_token.callback_confirmed?
          r.redirect(request_token.authorize_url)
        else
          r.redirect(request_token.authorize_url(:oauth_callback => callback_url))        
        end

        r.finish
      end
    end
  end
end
