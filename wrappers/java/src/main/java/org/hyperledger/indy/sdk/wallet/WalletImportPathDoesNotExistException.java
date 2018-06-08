package org.hyperledger.indy.sdk.wallet;

import org.hyperledger.indy.sdk.ErrorCode;
import org.hyperledger.indy.sdk.IndyException;

/**
 * Exception thrown if path provided to wallet import does not exist
 */
public class WalletImportPathDoesNotExistException extends IndyException
{
	private static final long serialVersionUID = 1829076830401150667L;
	private final static String message = "Structure error occurred during wallet operation.";

	/**
	 * Initializes a new WalletImportPathDoesNotExistException.
	 */
	public WalletImportPathDoesNotExistException()
    {
    	super(message, ErrorCode.WalletImportPathDoesNotExist.value());
    }
}