#!/usr/bin/ruby

Thread.abort_on_exception = true

require 'monitor'
require 'resolv'

DEBUG = false
QUEUE_DEBUG = false
RESOLVER_DEBUG = false

class WeaselQueue < Array
	def initialize(id)
		extend(MonitorMixin);
		@emptyCondition = new_cond
		@no_more_queues = false
		@id = id
	end

	def finish
		puts "[#{@id}:f] synchronizing" if QUEUE_DEBUG
		synchronize do
			puts "[#{@id}:f] setting no_more_queues" if QUEUE_DEBUG
			@no_more_queues = true
			@emptyCondition.broadcast
		end
	end

	def queue(from, item)
		throw "Somebody (#{from}) tries to queue an item but we have no_more_queues set already" if @no_more_queues
		puts "[#{@id}:q;#{from}] synchronizing" if QUEUE_DEBUG
		synchronize do
			puts "[#{@id}:q;#{from}] queuing" if QUEUE_DEBUG
			self << item
			puts "[#{@id}:q;#{from}] signaling" if QUEUE_DEBUG
			@emptyCondition.signal
			puts "[#{@id}:q;#{from}] done" if QUEUE_DEBUG
		end
	end

	def deQueue(from)
		result = nil
		puts "[#{@id}:d;#{from}] synchronizing" if QUEUE_DEBUG
		synchronize do
			puts "[#{@id}:d;#{from}] waiting; no_more_queues is #{@no_more_queues}, empty is #{empty?}" if QUEUE_DEBUG
			@emptyCondition.wait_while { not @no_more_queues and empty? };
			puts "[#{@id}:d;#{from}] waiting done" if QUEUE_DEBUG
			return nil if empty? and @no_more_queues
			result = shift
		end
		return result
	end

	def done?
		@no_more_queues and empty?
	end
end

class Resolver
	def initialize(id, inq,outq)
		@inQueue = inq
		@outQueue = outq
		@id = id

		@worker = Thread.new {
			worker
		}
	end

	def alive?
		@worker.alive?
	end

	def id
		@id
	end

	def worker
		t = Time.now.to_i / 60
		while not @inQueue.done?
			while true do
				puts "[#{@id}] trying to dequeue" if RESOLVER_DEBUG
				host = @inQueue.deQueue @id
				puts "[#{@id}] success.  got nil" if !host and RESOLVER_DEBUG
				break unless host
				puts "[#{@id}] dequeued "+host['hostname'] if RESOLVER_DEBUG

				begin
					host['address'] = Resolv.getaddress(host['hostname'])
					@outQueue.queue @id, host
					puts "[#{@id}] queued #{host['hostname']} #{host['address']} into outqueue <--------------------" if RESOLVER_DEBUG
				rescue Resolv::ResolvError
					@outQueue.queue @id, host
					puts "[#{@id}] resolve failed for #{host['hostname']}" if RESOLVER_DEBUG
				end
			end
			puts "[#{@id}] sleeping in resolver" if RESOLVER_DEBUG
			sleep 1
		end
		puts "[#{@id}] resolver done" if RESOLVER_DEBUG
	end
end


class MassResolver
	def initialize(num_resolvers)
		@inQueue = WeaselQueue.new "IQ"
		@outQueue = WeaselQueue.new "OQ"
		@num_resolvers = num_resolvers
	end

	# hosts is an array of hashes.  each hash has a hostname attribute.  afterwards
	# those that could be resolved have an address attribute too
	def resolve_many(hosts)

		master_thread = Thread.current
		resolvers = []
		resolvedhosts = []
		@num_resolvers.times { |i| resolvers << Resolver.new("R%03d"%[i], @inQueue, @outQueue) }

		Thread.new {
			while resolvers.size > 0 or not @outQueue.empty?
				while not @outQueue.empty? or not @inQueue.empty?
					if @outQueue.empty?
						puts "[Reader] sleeping in outthread" if DEBUG
						sleep 1
					end

					result = @outQueue.deQueue 'Reader'
					next unless result
					resolvedhosts << result
				end
				resolvers = resolvers.delete_if{|t| !t.alive?}

				if DEBUG
					puts "[Reader] outthread done."
					puts "[Reader] outQueue.empty? is #{@outQueue.empty?}"
					puts "[Reader] number of resolvers is #{resolvers.size}"
					puts "[Reader] orig hosts count: #{hosts.size}"
					puts "[Reader] resolved hosts count: #{resolvedhosts.size}"
				end

				if resolvers.size > 0
					if DEBUG
						puts "[Reader] sleeping in outthread, 2"
						puts "[Reader] still alive: "
						resolvers.each do |r|
							puts "[Reader] resolvers #{r.id}"
						end
					end
					sleep 1
				end
			end
			master_thread.wakeup
		}

		hosts.each do |host|
			@inQueue.queue( 'Pusher', host )
			puts "[Pusher] Queuing in #{host['hostname']}" if DEBUG
		end
		@inQueue.finish
		#@outQueue.finish
		#resolvers.each{ |r| r.finish }

		Thread.stop
		resolvedhosts
	end
end

#hosts = []
#hosts << { 'hostname' => 'asteria.debian.or.at' }
#MassResolver.new.resolve_many hosts
