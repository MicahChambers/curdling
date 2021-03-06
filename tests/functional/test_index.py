from __future__ import absolute_import, print_function, unicode_literals
from curdling.index import Index, PackageNotFound
from . import FIXTURE


def test_index_from_file():
    "It should be possible to index packages from files"

    # Given the following index
    index = Index(FIXTURE('index'))

    # When I index a file
    index.from_file(FIXTURE('storage1/gherkin-0.1.0.tar.gz'))

    # Then I see it inside of the index
    index.get('gherkin==0.1.0;gz').should.equal(
        FIXTURE('index/gherkin-0.1.0.tar.gz'),
    )

    # And that there's no wheel available yet
    index.get.when.called_with('gherkin==0.1.0;whl').should.throw(
        PackageNotFound,
    )

    # And I clean the mess
    index.delete()


def test_index_from_data():
    "It should be possible to index data from memory"

    # Given the following index
    index = Index(FIXTURE('index'))

    # When I index a file
    data = open(FIXTURE('storage1/gherkin-0.1.0.tar.gz'), 'rb').read()
    index.from_data(path='gherkin-0.1.0.tar.gz', data=data)

    # Then I see it inside of the index
    index.get('gherkin==0.1.0').should.equal(
        FIXTURE('index/gherkin-0.1.0.tar.gz'),
    )

    # And I clean the mess
    index.delete()


def test_index_scan():
    "It should be possible to scan for already existing folders"

    # Given that I have an index that points to a folder that already contains
    # packages
    index = Index(FIXTURE('storage1'))

    # When I scan the directory
    index.scan()

    # Then I can look for packages
    index.get('gherkin==0.1.0').should.equal(
        FIXTURE('storage1/gherkin-0.1.0.tar.gz'),
    )


def test_index_scan_when_there_is_no_dir():
    "Index.scan() should not fail when the dir does not exist"

    # Given that I have an index that points to a directory that already
    # contains packages
    index = Index('I know this directory does not exist')

    # When I scan the directory, I see it does not fail
    index.scan()
