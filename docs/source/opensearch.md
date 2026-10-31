# OpenSearch and Grafana

To set up visual dashboards of DMARC data, install OpenSearch and Grafana.

## Installation

OpenSearch: https://opensearch.org/docs/latest/install-and-configure/install-opensearch/index/
Grafana: https://grafana.com/docs/grafana/latest/setup-grafana/installation/

## Data streams and records retention

Starting in version 5.0.0, `parsedmarc` stores data in a separate
index for each day (or each month, with `monthly_indexes`), named after
the report's date, such as `dmarc_aggregate-2024-03-31`. That makes it
easy to comply with records retention regulations such as GDPR: delete
the indexes for the dates you no longer keep.

Set `use_data_streams = True` in the `[opensearch]` section to write to
[data streams] instead. Each report type then goes to one data stream
named like the indexes without the date: `dmarc_aggregate`,
`dmarc_failure`, and `smtp_tls`, with `index_prefix`, `index_suffix`, or
the `index_prefix_domain_map` prefix applied as usual. The cluster
creates the stream's backing indices (`.ds-dmarc_aggregate-000001`, …),
and an [ISM] policy you attach rolls them over and deletes old data, so
there is one stable name per report type and far fewer shards. Amazon
OpenSearch Serverless (`aws_service = aoss`) has no data streams or
ISM, so leave `use_data_streams` off there.

Before a parsedmarc process first saves to a stream, it puts an index
template named after the stream and creates the stream if it does not
exist yet. The template:

- matches exactly the stream's name, with no wildcard, so it never applies
  to the dated indexes;
- has priority 501 and sets `number_of_shards` and `number_of_replicas`
  from the configuration, for each new backing index;
- maps `@timestamp` as a date. Every document parsedmarc saves carries
  `@timestamp`: each record's begin date (`date_begin`) for aggregate
  reports, which is the report's begin date unless parsedmarc split a
  report spanning more than a day into daily records; the arrival date
  for failure reports; and the report's begin date for SMTP TLS reports.
  The other fields are mapped dynamically, as in the dated indexes.

parsedmarc puts the template again in every process, so changes made to
it directly do not last.

parsedmarc does not create or change any ISM policy. Here is an example
that rolls each stream over every 30 days, or sooner when a primary
shard reaches 50 GB, and deletes a backing index 180 days after it was
created. Its `ism_template` attaches it to every backing index the
listed streams create from now on. List the stream names themselves,
including any prefix or suffix: a `.ds-dmarc_aggregate-*` pattern does
not match the backing indices.

```text
PUT _plugins/_ism/policies/parsedmarc
{
  "policy": {
    "description": "parsedmarc data stream retention",
    "default_state": "hot",
    "states": [
      {
        "name": "hot",
        "actions": [
          {
            "rollover": {
              "min_index_age": "30d",
              "min_primary_shard_size": "50gb"
            }
          }
        ],
        "transitions": [
          {
            "state_name": "delete",
            "conditions": {"min_index_age": "180d"}
          }
        ]
      },
      {
        "name": "delete",
        "actions": [{"delete": {}}],
        "transitions": []
      }
    ],
    "ism_template": [
      {
        "index_patterns": ["dmarc_aggregate", "dmarc_failure", "smtp_tls"],
        "priority": 100
      }
    ]
  }
}
```

The `ism_template` only applies to backing indices created after the
policy. To attach the policy to the backing indices of a stream that
already exists:

```text
POST _plugins/_ism/add/dmarc_aggregate
{
  "policy_id": "parsedmarc"
}
```

`min_index_age` counts from when the backing index was created, not
from the report dates, so a backing index is deleted 180 days after it
was created, whatever dates the reports in it cover. If you need
retention by report date, keep using dated indexes and delete them by
name.

### Switching an existing installation to data streams

Dated indexes that already exist are left alone. They keep working next
to the streams: the shipped dashboards use the `dmarc_aggregate*`,
`dmarc_f*`, and `smtp_tls*` index patterns, which match both, and the
check for duplicate reports searches both, so a report that is already
in a dated index is not saved again into a stream. You can delete the
dated indexes when they age out of your retention period, or move their
documents into the streams. Documents saved by earlier releases have no
`@timestamp`, which a data stream requires, so add it while reindexing:

```text
POST _reindex
{
  "source": {"index": "dmarc_aggregate-*"},
  "dest": {"index": "dmarc_aggregate", "op_type": "create"},
  "script": {
    "lang": "painless",
    "source": "ctx._source['@timestamp'] = ctx._source.date_begin"
  }
}
```

Use `date_begin` for `smtp_tls-*` too, and `arrival_date` for
`dmarc_failure-*`. Delete the dated indexes once the reindex has
finished; until then, the dashboards count every document twice.

If saving fails with `cannot create the data stream dmarc_aggregate: an
index or alias with that name already exists`, an index or alias already
uses the stream's name. parsedmarc releases before 5.0.0 wrote to an
undated `dmarc_aggregate` index, for example. parsedmarc refuses to
write into such an index rather than mixing new documents into it. Move
its documents to a dated name, which the
dashboards still match, and delete it:

```text
POST _reindex
{
  "source": {"index": "dmarc_aggregate"},
  "dest": {"index": "dmarc_aggregate-legacy"}
}

DELETE dmarc_aggregate
```

[data streams]: https://docs.opensearch.org/latest/im-plugin/data-streams/
[ISM]: https://docs.opensearch.org/latest/im-plugin/ism/index/
