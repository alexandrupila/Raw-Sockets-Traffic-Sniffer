struct dnshdr
	{
		/** DNS query identification */
		uint16_t transactionID;
#if (BYTE_ORDER == LITTLE_ENDIAN)
		uint16_t
		/** Recursion desired flag */
			recursionDesired:1,
		/** Truncated flag */
			truncation:1,
		/** Authoritative answer flag */
			authoritativeAnswer:1,
		/** Operation Code */
			opcode:4,
		/** Query/Response flag */
			queryOrResponse:1,
		/** Return Code */
			responseCode:4,
		/** Checking disabled flag */
			checkingDisabled:1,
		/** Authenticated data flag */
			authenticData:1,
		/** Zero flag (Reserved) */
			zero:1,
		/** Recursion available flag */
			recursionAvailable:1;
#elif (BYTE_ORDER == BIG_ENDIAN)
		uint16_t
		/** Query/Response flag */
			queryOrResponse:1,
		/** Operation Code */
			opcode:4,
		/** Authoritative answer flag */
			authoritativeAnswer:1,
		/** Truncated flag */
			truncation:1,
		/** Recursion desired flag */
			recursionDesired:1,
		/** Recursion available flag */
			recursionAvailable:1,
		/** Zero flag (Reserved) */
			zero:1,
		/** Authenticated data flag */
			authenticData:1,
		/** Checking disabled flag */
			checkingDisabled:1,
		/** Return Code */
			responseCode:4;
#endif
		/** Number of DNS query records in packet */
		uint16_t numberOfQuestions;
		/** Number of DNS answer records in packet */
		uint16_t numberOfAnswers;
		/** Number of authority records in packet */
		uint16_t numberOfAuthority;
		/** Number of additional records in packet */
		uint16_t numberOfAdditional;
	};