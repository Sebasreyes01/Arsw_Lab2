package edu.eci.arsw.hostBlackLists.blacklistvalidator;

import java.util.LinkedList;
import java.util.List;

import edu.eci.arsw.hostBlackLists.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;

/**
 * @author Sebastián Reyes
 */
public class ValidatorThread extends Thread {

	private int rangeStart;
	private int rangeEnd;
	private int occurrencesQuantity;
	private String ip;
	private int checkedListsCount;
	private LinkedList<Integer> blackListOccurrences;
	
	/**
	 * Constructor of the class.
	 * @param rangeStart It is the beginning of the range of servers that is going to be checked.
	 * @param rangeEnd It is the end of the range of servers that is going to be checked.
	 * @param ip It is the ip address that is going to be checked.
	 */
	public ValidatorThread(int rangeStart, int rangeEnd, String ip) {
		this.rangeStart = rangeStart;
		this.rangeEnd = rangeEnd;
		this.ip = ip;
	}
	
	@Override
	public void run() {
		blackListOccurrences = new LinkedList<>();
		occurrencesQuantity = 0;
		HostBlacklistsDataSourceFacade skds = HostBlacklistsDataSourceFacade.getInstance();
		checkedListsCount = 0;
		for (int i = rangeStart; i <= rangeEnd && occurrencesQuantity < HostBlackListsValidator.BLACK_LIST_ALARM_COUNT; i++) {
			if(HostBlackListsValidator.occurrences.get() >= HostBlackListsValidator.BLACK_LIST_ALARM_COUNT) {
//				return;
				break;
			} else {
				checkedListsCount++;
				if (skds.isInBlackListServer(i, ip)) {
					blackListOccurrences.add(i);
					HostBlackListsValidator.occurrences.getAndAdd(1);
				}
			}
		}
	}
	
	/**
	 * @return The number of the lists where there was an occurrence.
	 */
	public List<Integer> listOccurrences() {
		return blackListOccurrences;
	}
	
	/**
	 * @return The number of lists checked.
	 */
	public int checkedLists() {
		return checkedListsCount;
	}

}
