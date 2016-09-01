#!/usr/bin/env ruby

require 'aws-sdk'
require 'net/http'
require 'json'
require 'uri'
require 'yaml'
require 'syslog/logger'


log = Syslog::Logger.new 's3-virusscan'
conf = YAML::load_file(__dir__ + '/s3-virusscan.conf')

Aws.config.update(region: conf['region'])
s3 = Aws::S3::Client.new()
sns = Aws::SNS::Client.new()

poller = Aws::SQS::QueuePoller.new(conf['queue'])

log.info "s3-virusscan started"

poller.poll do |msg|
  body = JSON.parse(msg.body)
  if body.key?('Records')
    body['Records'].each do |record|
      bucket = record['s3']['bucket']['name']
      key = URI.decode(record['s3']['object']['key']).gsub('+', ' ')
      log.debug "scanning s3://#{bucket}/#{key}..."
      begin
        resp = s3.get_object(
          response_target: '/tmp/target',
          bucket: bucket,
          key: key
        )
      rescue Aws::S3::Errors::NoSuchKey
        log.debug "s3://#{bucket}/#{key} does no longer exist"
        next
      end
      if system('clamscan /tmp/target')
        log.debug "s3://#{bucket}/#{key} was scanned without findings"
        status = 'OK'
      else
        log.error "s3://#{bucket}/#{key} is infected"
        sns.publish(
          topic_arn: conf['topic'],
          message: "s3://#{bucket}/#{key} is infected",
          subject: "s3-virusscan s3://#{bucket}",
          message_attributes: {
            "key" => {
              data_type: "String",
              string_value: "s3://#{bucket}/#{key}"
            }
          }
        )
        status = 'KO'
      end

      log.info "Response metadata"
      log.info resp.metadata

      log.info "File id: #{key} status: #{status}"
      metadata = resp.metadata
      if (metadata.has_key?("callback-url"))
        callbackurl = metadata["callback-url"]
        log.info "Callback #{callbackurl}"
        uri = URI(callbackurl)
        begin
          res = Net::HTTP.start(uri.host, uri.port, {:use_ssl => uri.scheme == 'https', :verify_mode => 0}) do |http|
            req = Net::HTTP::Post.new(uri)
            params = {"filename" => key, "status" => status}
            log.info "Response callback"
            log.info params
            req.set_form_data(params)
            http.request(req)
          end
        rescue
          log.error "Post callback error file: #{key}, url: #{callbackurl}"
        end
      end
      system('rm /tmp/target')
    end
  end
end

