package org.hyperledger.indy.sdk.wallet;

import org.hyperledger.indy.sdk.ErrorCode;
import org.hyperledger.indy.sdk.IndyException;

/**
 * Exception thrown if path provided to wallet export already exists
 */
public class WalletExportPathExistsException extends IndyException
{
	private static final long serialVersionUID = 1829076830401150667L;
	private final static String message = "Structure error occurred during wallet operation.";

	/**
	 * Initializes a new WalletExportPathExistsException.
	 */
	public WalletExportPathExistsException()
    {
    	super(message, ErrorCode.WalletExportPathExists.value());
    }
}