"""Thin ABI memory/status projection; the native fixture owns OS account rules."""
import ctypes as C
import os
import sys
import unittest
from unittest import mock

from abstraction.ipc import (Library, ServerExpectation, FrameError, OK, INVALID_ARGUMENT,
                             INTERNAL_ERROR, IO_ERROR, PROOF_UNAVAILABLE, NO_MEMORY)


class PrincipalProjection(unittest.TestCase):
    def library(self, query):
        library = Library.__new__(Library)
        library._current_principal = query
        return library

    def query(self, *, kind=2, payload=b"1000\0", status=OK, mutate=None):
        calls = []
        def query(out_kind, buffer, capacity, required):
            calls.append(capacity)
            out_kind._obj.value = kind
            required._obj.value = len(payload)
            if status != OK:
                return status
            if buffer is not None:
                C.memmove(buffer, payload, min(capacity, len(payload)))
                if mutate:
                    mutate(out_kind, buffer, capacity, required)
            return OK
        return query, calls

    def test_copies_owned_bytes_and_constructs_program_without_child(self):
        query, calls = self.query()
        library = self.library(query)
        with mock.patch('subprocess.Popen', side_effect=AssertionError('account subprocess')):
            self.assertEqual(library.current_principal(), (2, '1000'))
            program = os.path.abspath('folder/../runtime')
            expected = ServerExpectation.current_account(program, library=library)
        self.assertEqual(expected, ServerExpectation(2, '1000', os.path.normpath(program)))
        self.assertEqual(calls, [0, 5, 0, 5])

    def test_missing_optional_export_and_native_errors_never_fallback(self):
        with mock.patch('subprocess.Popen', side_effect=AssertionError('account subprocess')):
            with self.assertRaises(FrameError) as caught:
                self.library(None).current_principal()
            self.assertEqual(caught.exception.status, PROOF_UNAVAILABLE)
            for status in (IO_ERROR, NO_MEMORY, PROOF_UNAVAILABLE):
                query, calls = self.query(status=status)
                with self.subTest(status=status), self.assertRaises(FrameError) as caught:
                    self.library(query).current_principal()
                self.assertEqual(caught.exception.status, status)
                self.assertEqual(calls, [0])

    def test_query_kind_and_size_are_bounded(self):
        for kind, payload in ((0, b'1000\0'), (3, b'1000\0'), (2, b''), (2, b'\0'), (2, b'x'*65537)):
            query, calls = self.query(kind=kind, payload=payload)
            with self.subTest(kind=kind, size=len(payload)), self.assertRaises(FrameError) as caught:
                self.library(query).current_principal()
            self.assertEqual(caught.exception.status, INTERNAL_ERROR)
            self.assertEqual(calls, [0])

    def test_copy_refuses_bad_kind_length_terminator_embedded_nul_and_encoding(self):
        def kind(out, _buffer, _capacity, _required): out._obj.value = 1
        def length(_out, _buffer, capacity, required): required._obj.value = capacity + 1
        for payload, mutate in ((b'1000\0', kind), (b'1000\0', length), (b'1000x', None),
                                (b'1\0000\0', None), (b'\xff\0', None)):
            query, _ = self.query(payload=payload, mutate=mutate)
            with self.subTest(payload=payload, mutate=mutate), self.assertRaises(FrameError) as caught:
                self.library(query).current_principal()
            self.assertEqual(caught.exception.status, INTERNAL_ERROR)

    def test_changed_size_retry_is_finite_and_copy_error_propagates(self):
        for growing in (False, True):
            calls = []
            def query(kind, buffer, capacity, required):
                calls.append(capacity)
                kind._obj.value = 2
                if buffer is None:
                    required._obj.value = 2
                    return OK
                if growing or capacity < 5:
                    kind._obj.value = 0
                    required._obj.value = capacity + 3
                    return INVALID_ARGUMENT
                required._obj.value = 5
                C.memmove(buffer, b'1000\0', 5)
                return OK
            if growing:
                with self.assertRaises(FrameError) as caught:
                    self.library(query).current_principal()
                self.assertEqual(caught.exception.status, INVALID_ARGUMENT)
                self.assertEqual(len(calls), 4)
            else:
                self.assertEqual(self.library(query).current_principal(), (2, '1000'))
                self.assertEqual(calls, [0, 2, 5])
        def failed(kind, buffer, capacity, required):
            kind._obj.value = 2
            required._obj.value = 5
            return OK if buffer is None else IO_ERROR
        with self.assertRaises(FrameError) as caught:
            self.library(failed).current_principal()
        self.assertEqual(caught.exception.status, IO_ERROR)

    def test_program_validation_precedes_loading_and_default_disables_installed_lookup(self):
        for program in ('relative', '', None, b'/bytes', os.path.abspath('runtime')+'\0'):
            with self.subTest(program=program), mock.patch('abstraction.ipc.Library') as load:
                with self.assertRaises(ValueError): ServerExpectation.current_account(program)
                load.assert_not_called()
        with mock.patch('abstraction.ipc.Library') as load:
            load.return_value.current_principal.return_value = (2, '1000')
            ServerExpectation.current_account(os.path.abspath('runtime'))
            load.assert_called_once_with(allow_installed=False)


@unittest.skipUnless(os.environ.get('ABSTRACTION_IPC_LIBRARY'), 'explicit compiled shared client required')
class CompiledPrincipal(unittest.TestCase):
    def test_actual_shared_export_to_python_without_child_or_connection(self):
        library = Library(os.environ['ABSTRACTION_IPC_LIBRARY'], allow_installed=False)
        with mock.patch('subprocess.Popen', side_effect=AssertionError('query child')), \
             mock.patch.object(Library, 'select_runtime', side_effect=AssertionError('installation query')), \
             mock.patch.object(Library, 'activate_runtime', side_effect=AssertionError('runtime activation')):
            kind, principal = library.current_principal()
            expected = ServerExpectation.current_account(sys.executable, library=library)
        self.assertEqual(kind, 1 if sys.platform == 'win32' else 2)
        self.assertTrue(principal)
        self.assertEqual((expected.principal_kind, expected.principal), (kind, principal))
        print(f'PASS native current principal -> Python kind={kind} bytes={len(principal.encode())}; no query child')


if __name__ == '__main__': unittest.main()
