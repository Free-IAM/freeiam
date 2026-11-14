"""Update benchmark tables in README.md from pytest-benchmark CSV files."""

import argparse
import csv
from pathlib import Path


BACKENDS = (
    ('ldap', 'Python-LDAP'),
    ('freeiam', 'FreeIAM'),
    ('bonsai', 'Bonsai'),
    ('ldap3', 'LDAP3'),
)
FILTER_CASES = ('presence', 'equality', 'escaped', 'substring', 'extensible', 'nested', 'complex')
DN_CASES = ('user', 'multi_rdn', 'escaped', 'complex')


def read_csv(path):
    with path.open(newline='') as stream:
        return list(csv.DictReader(stream))


def value(row, digits=2):
    return f'{float(row["mean"]) * 1_000_000:.{digits}f}/{float(row["median"]) * 1_000_000:.{digits}f}'


def connection_table(rows):
    table = {}
    for row in rows:
        backend = row.get('param:client') or row.get('param:backend_spec') or row.get('param:async_client')
        name = row['name'].split('::', 1)[1]
        if name.startswith('test_sync_search'):
            test = 'Sync iter' if row['param:itering'] == 'True' else 'Sync no-iter'
        elif name.startswith('test_async_search'):
            test = 'Async iter' if row['param:itering'] == 'True' else 'Async no-iter'
        elif name.startswith('test_parallel_sync_search'):
            test = 'Parallel sync'
        elif name.startswith('test_parallel_async_search'):
            test = 'Parallel async'
        elif name.startswith('test_multiple_parallel_sync_search'):
            test = 'Multiple parallel sync'
        elif name.startswith('test_multiple_parallel_async_search'):
            test = 'Multiple parallel async'
        else:
            continue
        table[(backend, test)] = value(row)

    columns = (
        'Sync no-iter',
        'Sync iter',
        'Async no-iter',
        'Async iter',
        'Parallel sync',
        'Parallel async',
        'Multiple parallel sync',
        'Multiple parallel async',
    )
    lines = [
        '| Backend | ' + ' | '.join(columns) + ' |',
        '|---|' + '---:|' * len(columns),
    ]
    for backend, label in BACKENDS:
        cells = [table.get((backend, column), '-') for column in columns]
        lines.append(f'| {label} | ' + ' | '.join(cells) + ' |')
    return '\n'.join(lines)


def filter_table(rows):
    rows_by_key = {(row['param:case'], row['param:parser']): row for row in rows}
    lines = ['| Case | Lark (us) | libldap (us) |', '|---|---:|---:|']
    for case in FILTER_CASES:
        lark = rows_by_key.get((case, 'lark'))
        libldap = rows_by_key.get((case, 'libldap'))
        lines.append(f'| {case.title()} | {mean_us(lark)} | {mean_us(libldap)} |')
    return '\n'.join(lines)


def mean_us(row, digits=2):
    return '-' if row is None else f'{float(row["mean"]) * 1_000_000:.{digits}f}'


def dn_table(rows):
    operation_labels = (
        ('test_dn_parse_cached', 'Warm-cache parsing'),
        ('test_dn_parse_cold', 'Cold-cache parsing'),
        ('test_dn_equality', 'Equality'),
        ('test_dn_normalize', 'Normalization'),
        ('test_dn_compose', 'Composition'),
    )
    case_labels = {
        'user': 'User',
        'multi_rdn': 'Multi-valued RDN',
        'escaped': 'Escaped',
        'complex': 'Complex',
        '': '',
    }
    lines = ['| Operation | Case | Mean |', '|---|---|---:|']
    for prefix, operation in operation_labels:
        matching = [row for row in rows if f'::{prefix}' in row['name']]
        matching.sort(key=lambda row: DN_CASES.index(row['param:case']) if row['param:case'] else -1)
        for row in matching:
            case = case_labels[row['param:case']]
            if operation == 'Equality':
                case = 'Normalized multi-valued RDN'
            elif operation == 'Composition':
                case = 'User DN'
            lines.append(f'| {operation} | {case} | {mean_us(row, 3)} us |')
    return '\n'.join(lines)


def replace_table(readme, name, table):
    start = f'<!-- benchmark-table:{name}:start -->'
    end = f'<!-- benchmark-table:{name}:end -->'
    before, marker, remainder = readme.partition(start)
    if not marker:
        msg = f'Missing README marker: {start}'
        raise ValueError(msg)
    _, marker, after = remainder.partition(end)
    if not marker:
        msg = f'Missing README marker: {end}'
        raise ValueError(msg)
    return f'{before}{start}\n{table}\n{end}{after}'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--readme', type=Path, default=Path('README.md'))
    parser.add_argument('--connection', type=Path, default=Path('connection-benchmark.csv'))
    parser.add_argument('--filter', dest='filter_csv', type=Path, default=Path('filter-benchmark.csv'))
    parser.add_argument('--dn', type=Path, default=Path('dn-benchmark.csv'))
    args = parser.parse_args()

    readme = args.readme.read_text()
    readme = replace_table(readme, 'connection', connection_table(read_csv(args.connection)))
    readme = replace_table(readme, 'filter', filter_table(read_csv(args.filter_csv)))
    readme = replace_table(readme, 'dn', dn_table(read_csv(args.dn)))
    args.readme.write_text(readme)


if __name__ == '__main__':
    main()
