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

    authorization_attr = header_get_attr(event, 'Authorization')
    if authorization_attr.nil?
      return response(status: 403)
    elsif authorization_attr =~ /^Bearer (\S+)$/
      begin
        decoded_jwt = JWT.decode($1, ENV['JWT_SECRET'], true, { algorithm: 'HS256' })
        payload = decoded_jwt[0]
      rescue JWT::ImmatureSignature, JWT::ExpiredSignature
        return response(status: 401)
      rescue JWT::DecodeError
        return response(status: 403)
      end
    else
      return response(status: 403)
    end

    return response(body: payload['data'])
  end

  # '/auth/token'
  if event['path'] == '/auth/token'
    content_type_attr = header_get_attr(event, 'Content-Type')
    if (content_type_attr.nil? ||
        content_type_attr != 'application/json')
      return response(status: 415)
    end
    
    if (!event.has_key?('body') ||
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

def header_get_attr(event, case_sensitive_key)
  value = nil
  if event.has_key?('headers')
    key_value = event['headers'].find { |key, _| key.downcase == case_sensitive_key.downcase }
    if (!key_value.nil? && key_value.size == 2)
        value = key_value[1]
    end
  end

  return value
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
    exp: Time.now.to_i + 5,
    nbf: Time.now.to_i + 3
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
