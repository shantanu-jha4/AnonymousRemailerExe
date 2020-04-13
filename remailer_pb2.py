# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: remailer.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='remailer.proto',
  package='',
  syntax='proto3',
  serialized_options=None,
  serialized_pb=_b('\n\x0eremailer.proto\"\xfb\x01\n\x08\x41nonMssg\x12(\n\x0e\x63lient_request\x18\x01 \x01(\x0b\x32\x0e.ClientRequestH\x00\x12\x1c\n\x08ts_reply\x18\x02 \x01(\x0b\x32\x08.TSReplyH\x00\x12&\n\rerror_message\x18\x03 \x01(\x0b\x32\r.ErrorMessageH\x00\x12(\n\x0eremailer_hello\x18\x04 \x01(\x0b\x32\x0e.RemailerHelloH\x00\x12\x1c\n\x08ts_hello\x18\x05 \x01(\x0b\x32\x08.TSHelloH\x00\x12+\n\x0e\x65ncrypted_mssg\x18\x06 \x01(\x0b\x32\x11.EncryptedMessageH\x00\x42\n\n\x08message_\"%\n\x0c\x45rrorMessage\x12\x15\n\rerror_message\x18\x01 \x01(\t\"<\n\rClientRequest\x12\x17\n\x0fno_of_remailers\x18\x01 \x01(\r\x12\x12\n\npublic_key\x18\x02 \x01(\x0c\"O\n\x07TSReply\x12\x1f\n\tfull_path\x18\x01 \x03(\x0b\x32\x0c.PathElement\x12\r\n\x05ts_pk\x18\x02 \x01(\x0c\x12\x14\n\x0c\x65xit_node_pk\x18\x03 \x01(\x0c\"e\n\rRemailerHello\x12$\n\rping_response\x18\x01 \x01(\x0b\x32\r.PingResponse\x12\x14\n\x0cstring_agent\x18\x02 \x01(\t\x12\x18\n\x04self\x18\x03 \x01(\x0b\x32\n.Remailers\"W\n\x07TSHello\x12\"\n\x0cping_request\x18\x01 \x01(\x0b\x32\x0c.PingRequest\x12\x14\n\x0cstring_agent\x18\x02 \x01(\t\x12\x12\n\npublic_key\x18\x03 \x01(\x0c\"*\n\x0bPingRequest\x12\x0c\n\x04\x64\x61ta\x18\x01 \x01(\x0c\x12\r\n\x05nonce\x18\x02 \x01(\x0c\"\x1c\n\x0cPingResponse\x12\x0c\n\x04\x64\x61ta\x18\x01 \x01(\x0c\"2\n\x10\x45ncryptedMessage\x12\x0f\n\x07message\x18\x01 \x01(\x0c\x12\r\n\x05nonce\x18\x02 \x01(\x0c\"<\n\x10\x44\x65\x63ryptedMessage\x12\x17\n\x06header\x18\x01 \x01(\x0b\x32\x07.Header\x12\x0f\n\x07message\x18\x02 \x01(\x0c\"O\n\x05\x45mail\x12\x1f\n\tfull_path\x18\x01 \x03(\x0b\x32\x0c.PathElement\x12\x14\n\x0c\x61\x62out_sender\x18\x02 \x01(\x0c\x12\x0f\n\x07message\x18\x03 \x01(\t\".\n\x06Header\x12\x12\n\nip_address\x18\x01 \x01(\t\x12\x10\n\x08receiver\x18\x02 \x01(\t\"$\n\x0b\x43lientHello\x12\x15\n\rmajor_version\x18\x01 \x01(\r\"/\n\x04Keys\x12\x13\n\x0bprivate_key\x18\x01 \x01(\x0c\x12\x12\n\npublic_key\x18\x02 \x01(\x0c\"-\n\x0cRemailerList\x12\x1d\n\tremailers\x18\x01 \x03(\x0b\x32\n.Remailers\"J\n\x0bPathElement\x12\x18\n\x10remailer_on_path\x18\x01 \x01(\x0c\x12\x12\n\npublic_key\x18\x02 \x01(\x0c\x12\r\n\x05nonce\x18\x03 \x01(\x0c\"A\n\tRemailers\x12\x12\n\nip_address\x18\x01 \x01(\t\x12\x0c\n\x04port\x18\x02 \x01(\r\x12\x12\n\npublic_key\x18\x03 \x01(\x0c\x62\x06proto3')
)




_ANONMSSG = _descriptor.Descriptor(
  name='AnonMssg',
  full_name='AnonMssg',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='client_request', full_name='AnonMssg.client_request', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='ts_reply', full_name='AnonMssg.ts_reply', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='error_message', full_name='AnonMssg.error_message', index=2,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='remailer_hello', full_name='AnonMssg.remailer_hello', index=3,
      number=4, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='ts_hello', full_name='AnonMssg.ts_hello', index=4,
      number=5, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='encrypted_mssg', full_name='AnonMssg.encrypted_mssg', index=5,
      number=6, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
    _descriptor.OneofDescriptor(
      name='message_', full_name='AnonMssg.message_',
      index=0, containing_type=None, fields=[]),
  ],
  serialized_start=19,
  serialized_end=270,
)


_ERRORMESSAGE = _descriptor.Descriptor(
  name='ErrorMessage',
  full_name='ErrorMessage',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='error_message', full_name='ErrorMessage.error_message', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=272,
  serialized_end=309,
)


_CLIENTREQUEST = _descriptor.Descriptor(
  name='ClientRequest',
  full_name='ClientRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='no_of_remailers', full_name='ClientRequest.no_of_remailers', index=0,
      number=1, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='public_key', full_name='ClientRequest.public_key', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=311,
  serialized_end=371,
)


_TSREPLY = _descriptor.Descriptor(
  name='TSReply',
  full_name='TSReply',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='full_path', full_name='TSReply.full_path', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='ts_pk', full_name='TSReply.ts_pk', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='exit_node_pk', full_name='TSReply.exit_node_pk', index=2,
      number=3, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=373,
  serialized_end=452,
)


_REMAILERHELLO = _descriptor.Descriptor(
  name='RemailerHello',
  full_name='RemailerHello',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='ping_response', full_name='RemailerHello.ping_response', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='string_agent', full_name='RemailerHello.string_agent', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='self', full_name='RemailerHello.self', index=2,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=454,
  serialized_end=555,
)


_TSHELLO = _descriptor.Descriptor(
  name='TSHello',
  full_name='TSHello',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='ping_request', full_name='TSHello.ping_request', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='string_agent', full_name='TSHello.string_agent', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='public_key', full_name='TSHello.public_key', index=2,
      number=3, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=557,
  serialized_end=644,
)


_PINGREQUEST = _descriptor.Descriptor(
  name='PingRequest',
  full_name='PingRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='data', full_name='PingRequest.data', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='nonce', full_name='PingRequest.nonce', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=646,
  serialized_end=688,
)


_PINGRESPONSE = _descriptor.Descriptor(
  name='PingResponse',
  full_name='PingResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='data', full_name='PingResponse.data', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=690,
  serialized_end=718,
)


_ENCRYPTEDMESSAGE = _descriptor.Descriptor(
  name='EncryptedMessage',
  full_name='EncryptedMessage',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='message', full_name='EncryptedMessage.message', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='nonce', full_name='EncryptedMessage.nonce', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=720,
  serialized_end=770,
)


_DECRYPTEDMESSAGE = _descriptor.Descriptor(
  name='DecryptedMessage',
  full_name='DecryptedMessage',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='header', full_name='DecryptedMessage.header', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='message', full_name='DecryptedMessage.message', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=772,
  serialized_end=832,
)


_EMAIL = _descriptor.Descriptor(
  name='Email',
  full_name='Email',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='full_path', full_name='Email.full_path', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='about_sender', full_name='Email.about_sender', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='message', full_name='Email.message', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=834,
  serialized_end=913,
)


_HEADER = _descriptor.Descriptor(
  name='Header',
  full_name='Header',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='ip_address', full_name='Header.ip_address', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='receiver', full_name='Header.receiver', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=915,
  serialized_end=961,
)


_CLIENTHELLO = _descriptor.Descriptor(
  name='ClientHello',
  full_name='ClientHello',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='major_version', full_name='ClientHello.major_version', index=0,
      number=1, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=963,
  serialized_end=999,
)


_KEYS = _descriptor.Descriptor(
  name='Keys',
  full_name='Keys',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='private_key', full_name='Keys.private_key', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='public_key', full_name='Keys.public_key', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1001,
  serialized_end=1048,
)


_REMAILERLIST = _descriptor.Descriptor(
  name='RemailerList',
  full_name='RemailerList',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='remailers', full_name='RemailerList.remailers', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1050,
  serialized_end=1095,
)


_PATHELEMENT = _descriptor.Descriptor(
  name='PathElement',
  full_name='PathElement',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='remailer_on_path', full_name='PathElement.remailer_on_path', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='public_key', full_name='PathElement.public_key', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='nonce', full_name='PathElement.nonce', index=2,
      number=3, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1097,
  serialized_end=1171,
)


_REMAILERS = _descriptor.Descriptor(
  name='Remailers',
  full_name='Remailers',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='ip_address', full_name='Remailers.ip_address', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='port', full_name='Remailers.port', index=1,
      number=2, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='public_key', full_name='Remailers.public_key', index=2,
      number=3, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1173,
  serialized_end=1238,
)

_ANONMSSG.fields_by_name['client_request'].message_type = _CLIENTREQUEST
_ANONMSSG.fields_by_name['ts_reply'].message_type = _TSREPLY
_ANONMSSG.fields_by_name['error_message'].message_type = _ERRORMESSAGE
_ANONMSSG.fields_by_name['remailer_hello'].message_type = _REMAILERHELLO
_ANONMSSG.fields_by_name['ts_hello'].message_type = _TSHELLO
_ANONMSSG.fields_by_name['encrypted_mssg'].message_type = _ENCRYPTEDMESSAGE
_ANONMSSG.oneofs_by_name['message_'].fields.append(
  _ANONMSSG.fields_by_name['client_request'])
_ANONMSSG.fields_by_name['client_request'].containing_oneof = _ANONMSSG.oneofs_by_name['message_']
_ANONMSSG.oneofs_by_name['message_'].fields.append(
  _ANONMSSG.fields_by_name['ts_reply'])
_ANONMSSG.fields_by_name['ts_reply'].containing_oneof = _ANONMSSG.oneofs_by_name['message_']
_ANONMSSG.oneofs_by_name['message_'].fields.append(
  _ANONMSSG.fields_by_name['error_message'])
_ANONMSSG.fields_by_name['error_message'].containing_oneof = _ANONMSSG.oneofs_by_name['message_']
_ANONMSSG.oneofs_by_name['message_'].fields.append(
  _ANONMSSG.fields_by_name['remailer_hello'])
_ANONMSSG.fields_by_name['remailer_hello'].containing_oneof = _ANONMSSG.oneofs_by_name['message_']
_ANONMSSG.oneofs_by_name['message_'].fields.append(
  _ANONMSSG.fields_by_name['ts_hello'])
_ANONMSSG.fields_by_name['ts_hello'].containing_oneof = _ANONMSSG.oneofs_by_name['message_']
_ANONMSSG.oneofs_by_name['message_'].fields.append(
  _ANONMSSG.fields_by_name['encrypted_mssg'])
_ANONMSSG.fields_by_name['encrypted_mssg'].containing_oneof = _ANONMSSG.oneofs_by_name['message_']
_TSREPLY.fields_by_name['full_path'].message_type = _PATHELEMENT
_REMAILERHELLO.fields_by_name['ping_response'].message_type = _PINGRESPONSE
_REMAILERHELLO.fields_by_name['self'].message_type = _REMAILERS
_TSHELLO.fields_by_name['ping_request'].message_type = _PINGREQUEST
_DECRYPTEDMESSAGE.fields_by_name['header'].message_type = _HEADER
_EMAIL.fields_by_name['full_path'].message_type = _PATHELEMENT
_REMAILERLIST.fields_by_name['remailers'].message_type = _REMAILERS
DESCRIPTOR.message_types_by_name['AnonMssg'] = _ANONMSSG
DESCRIPTOR.message_types_by_name['ErrorMessage'] = _ERRORMESSAGE
DESCRIPTOR.message_types_by_name['ClientRequest'] = _CLIENTREQUEST
DESCRIPTOR.message_types_by_name['TSReply'] = _TSREPLY
DESCRIPTOR.message_types_by_name['RemailerHello'] = _REMAILERHELLO
DESCRIPTOR.message_types_by_name['TSHello'] = _TSHELLO
DESCRIPTOR.message_types_by_name['PingRequest'] = _PINGREQUEST
DESCRIPTOR.message_types_by_name['PingResponse'] = _PINGRESPONSE
DESCRIPTOR.message_types_by_name['EncryptedMessage'] = _ENCRYPTEDMESSAGE
DESCRIPTOR.message_types_by_name['DecryptedMessage'] = _DECRYPTEDMESSAGE
DESCRIPTOR.message_types_by_name['Email'] = _EMAIL
DESCRIPTOR.message_types_by_name['Header'] = _HEADER
DESCRIPTOR.message_types_by_name['ClientHello'] = _CLIENTHELLO
DESCRIPTOR.message_types_by_name['Keys'] = _KEYS
DESCRIPTOR.message_types_by_name['RemailerList'] = _REMAILERLIST
DESCRIPTOR.message_types_by_name['PathElement'] = _PATHELEMENT
DESCRIPTOR.message_types_by_name['Remailers'] = _REMAILERS
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

AnonMssg = _reflection.GeneratedProtocolMessageType('AnonMssg', (_message.Message,), dict(
  DESCRIPTOR = _ANONMSSG,
  __module__ = 'remailer_pb2'
  # @@protoc_insertion_point(class_scope:AnonMssg)
  ))
_sym_db.RegisterMessage(AnonMssg)

ErrorMessage = _reflection.GeneratedProtocolMessageType('ErrorMessage', (_message.Message,), dict(
  DESCRIPTOR = _ERRORMESSAGE,
  __module__ = 'remailer_pb2'
  # @@protoc_insertion_point(class_scope:ErrorMessage)
  ))
_sym_db.RegisterMessage(ErrorMessage)

ClientRequest = _reflection.GeneratedProtocolMessageType('ClientRequest', (_message.Message,), dict(
  DESCRIPTOR = _CLIENTREQUEST,
  __module__ = 'remailer_pb2'
  # @@protoc_insertion_point(class_scope:ClientRequest)
  ))
_sym_db.RegisterMessage(ClientRequest)

TSReply = _reflection.GeneratedProtocolMessageType('TSReply', (_message.Message,), dict(
  DESCRIPTOR = _TSREPLY,
  __module__ = 'remailer_pb2'
  # @@protoc_insertion_point(class_scope:TSReply)
  ))
_sym_db.RegisterMessage(TSReply)

RemailerHello = _reflection.GeneratedProtocolMessageType('RemailerHello', (_message.Message,), dict(
  DESCRIPTOR = _REMAILERHELLO,
  __module__ = 'remailer_pb2'
  # @@protoc_insertion_point(class_scope:RemailerHello)
  ))
_sym_db.RegisterMessage(RemailerHello)

TSHello = _reflection.GeneratedProtocolMessageType('TSHello', (_message.Message,), dict(
  DESCRIPTOR = _TSHELLO,
  __module__ = 'remailer_pb2'
  # @@protoc_insertion_point(class_scope:TSHello)
  ))
_sym_db.RegisterMessage(TSHello)

PingRequest = _reflection.GeneratedProtocolMessageType('PingRequest', (_message.Message,), dict(
  DESCRIPTOR = _PINGREQUEST,
  __module__ = 'remailer_pb2'
  # @@protoc_insertion_point(class_scope:PingRequest)
  ))
_sym_db.RegisterMessage(PingRequest)

PingResponse = _reflection.GeneratedProtocolMessageType('PingResponse', (_message.Message,), dict(
  DESCRIPTOR = _PINGRESPONSE,
  __module__ = 'remailer_pb2'
  # @@protoc_insertion_point(class_scope:PingResponse)
  ))
_sym_db.RegisterMessage(PingResponse)

EncryptedMessage = _reflection.GeneratedProtocolMessageType('EncryptedMessage', (_message.Message,), dict(
  DESCRIPTOR = _ENCRYPTEDMESSAGE,
  __module__ = 'remailer_pb2'
  # @@protoc_insertion_point(class_scope:EncryptedMessage)
  ))
_sym_db.RegisterMessage(EncryptedMessage)

DecryptedMessage = _reflection.GeneratedProtocolMessageType('DecryptedMessage', (_message.Message,), dict(
  DESCRIPTOR = _DECRYPTEDMESSAGE,
  __module__ = 'remailer_pb2'
  # @@protoc_insertion_point(class_scope:DecryptedMessage)
  ))
_sym_db.RegisterMessage(DecryptedMessage)

Email = _reflection.GeneratedProtocolMessageType('Email', (_message.Message,), dict(
  DESCRIPTOR = _EMAIL,
  __module__ = 'remailer_pb2'
  # @@protoc_insertion_point(class_scope:Email)
  ))
_sym_db.RegisterMessage(Email)

Header = _reflection.GeneratedProtocolMessageType('Header', (_message.Message,), dict(
  DESCRIPTOR = _HEADER,
  __module__ = 'remailer_pb2'
  # @@protoc_insertion_point(class_scope:Header)
  ))
_sym_db.RegisterMessage(Header)

ClientHello = _reflection.GeneratedProtocolMessageType('ClientHello', (_message.Message,), dict(
  DESCRIPTOR = _CLIENTHELLO,
  __module__ = 'remailer_pb2'
  # @@protoc_insertion_point(class_scope:ClientHello)
  ))
_sym_db.RegisterMessage(ClientHello)

Keys = _reflection.GeneratedProtocolMessageType('Keys', (_message.Message,), dict(
  DESCRIPTOR = _KEYS,
  __module__ = 'remailer_pb2'
  # @@protoc_insertion_point(class_scope:Keys)
  ))
_sym_db.RegisterMessage(Keys)

RemailerList = _reflection.GeneratedProtocolMessageType('RemailerList', (_message.Message,), dict(
  DESCRIPTOR = _REMAILERLIST,
  __module__ = 'remailer_pb2'
  # @@protoc_insertion_point(class_scope:RemailerList)
  ))
_sym_db.RegisterMessage(RemailerList)

PathElement = _reflection.GeneratedProtocolMessageType('PathElement', (_message.Message,), dict(
  DESCRIPTOR = _PATHELEMENT,
  __module__ = 'remailer_pb2'
  # @@protoc_insertion_point(class_scope:PathElement)
  ))
_sym_db.RegisterMessage(PathElement)

Remailers = _reflection.GeneratedProtocolMessageType('Remailers', (_message.Message,), dict(
  DESCRIPTOR = _REMAILERS,
  __module__ = 'remailer_pb2'
  # @@protoc_insertion_point(class_scope:Remailers)
  ))
_sym_db.RegisterMessage(Remailers)


# @@protoc_insertion_point(module_scope)
