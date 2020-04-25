# Toplevel Pubnub module.
module Pubnub
  # Holds grant functionality
  class GrantToken < PAM
    include Concurrent::Async
    include Pubnub::Validator::GrantToken

    def initialize(options, app)
      @event = :grant_token
      super
      @ttl ||= Pubnub::Constants::DEFAULT_TTL
      @permissions = default_permissions.deep_merge(options[:permissions])
    end

    def fire
      Pubnub.logger.debug('Pubnub::GrantToken') { "Fired event #{self.class}" }

      body = Formatter.format_message(parameters, @cipher_key, false)
      response = send_request(body)

      envelopes = fire_callbacks(handle(response, uri))
      finalize_event(envelopes)
      envelopes
    end

    private

    def current_operation
      Pubnub::Constants::OPERATION_GRANT_TOKEN
    end

    def parameters(signature = false)
      {
        ttl: @ttl,
        timestamp: @timestamp,
        permissions: @permissions,
      }
    end

    def path
      '/' + [
        'v3',
        'pam',
        @subscribe_key,
        'grant',
      ].join('/')
    end

    def default_permissions
      {
        resources: {
          channels: {},
          groups: {},
          users: {},
          spaces: {},
        },
        patterns: {
          channels: {},
          groups: {},
          users: {},
          spaces: {},
        },
        meta: {}
      }
    end
  end
end
