package org.hyperledger.indy.sdk.wallet;

import org.hyperledger.indy.sdk.ErrorCode;
import org.hyperledger.indy.sdk.IndyException;

/**
 * Exception thrown if the wallet is not empty, but it is required (currently only when importing)
 */
public class WalletNotEmptyException extends IndyException
{
	private static final long serialVersionUID = 1829076830401150667L;
	private final static String message = "Structure error occurred during wallet operation.";

	/**
	 * Initializes a new WalletNotEmptyException.
	 */
	public WalletNotEmptyException()
    {
    	super(message, ErrorCode.WalletNotEmpty.value());
    }
}