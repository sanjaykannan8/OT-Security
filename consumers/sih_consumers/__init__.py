"""Independent persistence/search/notification/archive pipelines. Each has its own consumer group and
commits offsets only after its durable write succeeds; none is coupled to the detection job."""
