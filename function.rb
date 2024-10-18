# frozen_string_literal: true

require 'json'
require 'jwt'
require 'pp'

def main(event:, context:)
  # You shouldn't need to use context, but its fields are explained here:
  # https://docs.aws.amazon.com/lambda/latest/dg/ruby-context.html

  # handle errors
  routes = { '/' => 'GET', '/auth/token' => 'POST' }

  if !event.has_key?('path') || !routes.has_key?(event['path'])
    return response(status: 404)
  end
  
  if !event.has_key?('httpMethod') || event['httpMethod'] != routes[event['path']]
    return response(status: 405)
  end

  # '/'
  if event['path'] == '/'
    payload = nil
    if !event.has_key?('headers') || !event['headers'].has_key?('Authorization')
      return response(status: 403)
    elsif event['headers']['Authorization'] =~ /^Bearer (\S+)$/
      begin
        decoded_jwt = JWT.decode($1, ENV['JWT_SECRET'], true, { algorithm: 'HS256' })
        payload = decoded_jwt[0]
      rescue JWT::DecodeError
        return response(status: 403)
      end
    end

    # check that decoded_jwt has all its parts.
    # The first entry is the encoded payload, 
    # and the second is the algorithm used to decode
    required_fields = [ 'data', 'exp', 'nbf' ]
    if (payload.nil? ||
        !required_fields.all? { |field| payload.has_key?(field) })
      return response(status: 403)
    else
      return response(body: payload['data'])
    end
  end

  # '/auth/token'
  if event['path'] == '/auth/token'
    proper_content_type = true
    if event.has_key?('headers')
      content_type = event['headers'].find { |key, _| key.downcase == 'Content-Type'.downcase }
      if (content_type.nil? || content_type.size != 2 ||
         event['headers'][content_type[0]] != 'application/json')
         proper_content_type = false
      end
    else
      proper_content_type = false
    end

    if !proper_content_type
      return response(status: 415)
    elsif (!event.has_key?('body') ||
        !valid_json?(event['body']))
      return response(status: 422)
    else
      payload = {
        'data': JSON.parse(event['body']),
        'exp': Time.now.to_i + 5,
        'nbf': Time.now.to_i + 2
      }

      token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'

      return response(body: { 'token' => token }, status: 201)
    end
  end
end

def response(body: nil, status: 200)
  {
    body: body ? body.to_json + "\n" : '',
    statusCode: status
  }
end

def valid_json?(string)
  begin
    JSON.parse string
    true
  rescue JSON::ParserError, TypeError => e
    false
  end
end

if $PROGRAM_NAME == __FILE__
  # If you run this file directly via `ruby function.rb` the following code
  # will execute. You can use the code below to help you test your functions
  # without needing to deploy first.
  ENV['JWT_SECRET'] = 'NOTASECRET'

  # Call /token
  PP.pp main(context: {}, event: {
               'body' => '{"name": "bboe"}',
               'headers' => { 'Content-Type' => 'application/json' },
               'httpMethod' => 'POST',
               'path' => '/auth/token'
             })

  # Generate a token
  payload = {
    data: { user_id: 128 },
    exp: Time.now.to_i + 1,
    nbf: Time.now.to_i
  }
  token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
  # Call /
  PP.pp main(context: {}, event: {
               'headers' => { 'Authorization' => "Bearer #{token}",
                              'Content-Type' => 'application/json' },
               'httpMethod' => 'GET',
               'path' => '/'
             })
end
