#!/usr/bin/env ruby

require 'aws-sdk'
require 'net/http'
require 'json'
require 'uri'
require 'yaml'
require 'syslog/logger'

# 1GB
LIMIT_SIZE = 1000000000

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
      log.info "scanning s3://#{bucket}/#{key}..."
      begin
        head_response = s3.head_object(
          bucket: bucket,
          key: key
        )
        filesize = head_response.content_length
        log.info "s3://#{bucket}/#{key} file size : #{filesize}"
        if filesize <= LIMIT_SIZE
          log.info "s3://#{bucket}/#{key} is under the limitation"
          get_response = s3.get_object(
            response_target: '/tmp/target',
            bucket: bucket,
            key: key
          )
          if system('clamscan /tmp/target')
            log.info "s3://#{bucket}/#{key} was scanned without findings"
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
        else
          status = 'OK'
          log.info "s3://#{bucket}/#{key} was not scanned because it reach the size limit"
        end
      rescue
        log.info "s3://#{bucket}/#{key} does no longer exist"
        next
      end

      log.info "Response metadata"
      log.info head_response.metadata

      log.info "File id: #{key} status: #{status}"
      metadata = head_response.metadata
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
          log.info "Post callback error file: #{key}, url: #{callbackurl}"
        end
      end
      system('rm /tmp/target')
    end
  end
end

