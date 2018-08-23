/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.eci.arsw.hostBlackLists.blacklistvalidator;

import edu.eci.arsw.hostBlackLists.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author Sebastián Reyes
 */
public class HostBlackListsValidator {

    public static final int BLACK_LIST_ALARM_COUNT=5;
    private static final Logger LOG = Logger.getLogger(HostBlackListsValidator.class.getName());
    public static AtomicInteger occurrences = new AtomicInteger(0);
    
    /**
     * Check the given host's IP address in all the available black lists,
     * and report it as NOT Trustworthy when such IP was reported in at least
     * BLACK_LIST_ALARM_COUNT lists, or as Trustworthy in any other case.
     * The search is not exhaustive: When the number of occurrences is equal to
     * BLACK_LIST_ALARM_COUNT, the search is finished, the host reported as
     * NOT Trustworthy, and the list of the five blacklists returned.
     * @param ipaddress suspicious host's IP address.
     * @return  Blacklists numbers where the given host's IP address was found.
     */
    public List<Integer> checkHost(String ipaddress,int N){
    	HostBlacklistsDataSourceFacade skds = HostBlacklistsDataSourceFacade.getInstance();
    	ArrayList<ValidatorThread> validatorThreadList = new ArrayList<ValidatorThread>();
    	for(int i = 0;i < N-1;i++) {
			validatorThreadList.add(new ValidatorThread((skds.getRegisteredServersCount() / N) * i,(skds.getRegisteredServersCount() / N) * (i+1) - 1,ipaddress));
		}
    	validatorThreadList.add(new ValidatorThread((skds.getRegisteredServersCount() / N) * (N-1),((skds.getRegisteredServersCount() / N) * (N - 1) + (skds.getRegisteredServersCount() / N) + (skds.getRegisteredServersCount() % N)) - 1,ipaddress));
		for(int i = 0;i < validatorThreadList.size();i++) {
    		validatorThreadList.get(i).start();
    	}
    	for(int i = 0;i < validatorThreadList.size();i++) {
    		try {
				validatorThreadList.get(i).join();
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
    	}
    	int checkedListsCount = 0;
    	for(int i = 0;i < validatorThreadList.size();i++) {
    		checkedListsCount += validatorThreadList.get(i).checkedLists();
    	}
    	if (occurrences.get() >= BLACK_LIST_ALARM_COUNT) {
			skds.reportAsNotTrustworthy(ipaddress);
		} else {
			skds.reportAsTrustworthy(ipaddress);
		}
    	for(int i = 1;i < validatorThreadList.size();i++) {
    		validatorThreadList.get(0).listOccurrences().addAll(validatorThreadList.get(i).listOccurrences());
    	}
    	LOG.log(Level.INFO, "Checked Black Lists:{0} of {1}", new Object[]{checkedListsCount, skds.getRegisteredServersCount()});
    	return validatorThreadList.get(0).listOccurrences();
    }
}

