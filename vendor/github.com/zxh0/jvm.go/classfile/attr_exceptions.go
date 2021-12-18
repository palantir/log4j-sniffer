package classfile

/*
Exceptions_attribute {
    u2 attribute_name_index;
    u4 attribute_length;
    u2 number_of_exceptions;
    u2 exception_index_table[number_of_exceptions];
}
*/
type ExceptionsAttribute struct {
	ExceptionIndexTable []uint16
}

func readExceptionsAttribute(reader *ClassReader) ExceptionsAttribute {
	return ExceptionsAttribute{
		ExceptionIndexTable: reader.readUint16s(),
	}
}
