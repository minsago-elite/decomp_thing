/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.program.database.data;

import java.io.IOException;

import db.DBRecord;
import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.database.DBObjectCache;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.InvalidNameException;
import ghidra.util.UniversalID;
import ghidra.util.exception.DuplicateNameException;

/**
 * Database implementation for a Pointer data type.
 */
class PointerDB extends DataTypeDB implements Pointer {

	private static final SettingsDefinition[] POINTER_SETTINGS_DEFINITIONS =
		new SettingsDefinition[] { MutabilitySettingsDefinition.DEF };

	private PointerDBAdapter adapter;

	private String displayName; // lazy initialization

	/**
	 * <code>isEquivalentActive</code> is used to break cyclical recursion when
	 * performing an {@link #isEquivalent(DataType)} checks on pointers which must
	 * also check the base datatype equivelency.
	 */
	private ThreadLocal<Boolean> isEquivalentActive = ThreadLocal.withInitial(() -> Boolean.FALSE);

	/**
	 * Constructor
	 * 
	 * @param dataMgr
	 * @param cache
	 * @param adapter
	 * @param record
	 */
	public PointerDB(DataTypeManagerDB dataMgr, DBObjectCache<DataTypeDB> cache,
			PointerDBAdapter adapter, DBRecord record) {
		super(dataMgr, cache, record);
		this.adapter = adapter;
	}

	@Override
	protected long doGetCategoryID() {
        try {

		return record.getLongValue(PointerDBAdapter.PTR_CATEGORY_COL);
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	protected String doGetName() {
        try {

		DataType dt = getDataType();
		// -1 length indicates default size from data organization
		int storedLen = record.getByteValue(PointerDBAdapter.PTR_LENGTH_COL);
		String lenStr = storedLen > 0 ? Integer.toString(storedLen * 8) : "";
		if (dt == null) {
			return PointerDataType.POINTER_NAME + lenStr;
		}
		return dt.getName() + " *" + lenStr;
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	public String toString() {
        try {

		return getName(); // always include pointer length
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	public DataType getDataType() {
        try {

        checkOwnedCurrent();
		if (dataMgr.isOwnedStrict()) dataMgr.acquireOwnedUnchecked(); else lock.acquire();
		try {
			checkIsValid();
			return dataMgr.getDataType(record.getLongValue(PointerDBAdapter.PTR_DT_ID_COL));
		}
		finally {
			lock.release();
		}
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	public SettingsDefinition[] getSettingsDefinitions() {
        try {

		return POINTER_SETTINGS_DEFINITIONS;
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	protected void refreshName() {
        try {

		super.refreshName();
		displayName = null;
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	protected boolean refresh() {
        try {

		try {
			DBRecord rec = adapter.getRecord(key);
            if (dataMgr.isOwnedStrict()) {
                dataMgr.requireOwnedLive();
                requireOwnedMatchingRow(rec);
            }
			if (rec != null) {
				record = rec;
				return super.refresh();
			}
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		return false;
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	public final DataType clone(DataTypeManager dtm) {
        DataTypeManagerDB.checkOwnedPointerCopy(this, dtm);
        try {
        checkOwnedCurrent();
        if (dtm == dataMgr) return this;
        return PointerDataType.copyForManager(this, dtm);
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	public DataType copy(DataTypeManager dtm) {
        try {

		return clone(dtm);
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	public String getDisplayName() {
        try {

		String localDisplayName = displayName;
		if (localDisplayName != null && !isInvalid()) {
			return localDisplayName;
		}
		if (dataMgr.isOwnedStrict()) dataMgr.acquireOwnedUnchecked(); else lock.acquire();
		try {
			checkIsValid();
			if (displayName == null) {
				// NOTE: Pointer display name only specifies length if null base type
				DataType dt = getDataType();
				if (dt == null) {
					displayName = PointerDataType.POINTER_NAME;
					if (!hasLanguageDependantLength()) {
						displayName += Integer.toString(getLength() * 8);
					}
				}
				else {
					displayName = dt.getDisplayName() + " *";
				}
			}
			return displayName;
		}
		finally {
			lock.release();
		}
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	public String getMnemonic(Settings settings) {
        try {

		if (dataMgr.isOwnedStrict()) dataMgr.acquireOwnedUnchecked(); else lock.acquire();
		try {
			checkIsValid();
			DataType dataType = getDataType();
			if (dataType == null || dataType == DataType.DEFAULT) {
				return "addr";
			}
			return dataType.getMnemonic(settings) + " *";
		}
		finally {
			lock.release();
		}
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	public boolean hasLanguageDependantLength() {
        try {

        checkOwnedCurrent();
		if (dataMgr.isOwnedStrict()) dataMgr.acquireOwnedUnchecked(); else lock.acquire();
		try {
			checkIsValid();
			return record.getByteValue(PointerDBAdapter.PTR_LENGTH_COL) <= 0;
		}
		finally {
			lock.release();
		}
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	public int getLength() {
        try {

        checkOwnedCurrent();
		if (dataMgr.isOwnedStrict()) dataMgr.acquireOwnedUnchecked(); else lock.acquire();
		try {
			checkIsValid();
			int len = record.getByteValue(PointerDBAdapter.PTR_LENGTH_COL);
			if (len <= 0) {
				len = dataMgr.getDataOrganization().getPointerSize();
			}
			return len;
		}
		finally {
			lock.release();
		}
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	public int getAlignedLength() {
        try {

		// assume pointers are never padded
		return getLength();
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	public String getDescription() {
        try {

		if (dataMgr.isOwnedStrict()) dataMgr.acquireOwnedUnchecked(); else lock.acquire();
		try {
			checkIsValid();
			StringBuffer sbuf = new StringBuffer();
			if (!hasLanguageDependantLength()) {
				sbuf.append(Integer.toString(getLength() * 8));
				sbuf.append("-bit ");
			}
			sbuf.append(PointerDataType.POINTER_NAME);
			DataType dt = getDataType();
			if (dt != null) {
				sbuf.append(" to ");
				if (dt instanceof Pointer) {
					sbuf.append(getDataType().getDescription());
				}
				else {
					sbuf.append(getDataType().getName());
				}
			}
			return sbuf.toString();
		}
		finally {
			lock.release();
		}
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
        try {

		if (dataMgr.isOwnedStrict()) dataMgr.acquireOwnedUnchecked(); else lock.acquire();
		try {
			checkIsValid();
			return PointerDataType.getAddressValue(buf, getLength(), settings);
		}
		catch (IllegalArgumentException exc) {
			return null;
		}
		finally {
			lock.release();
		}
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	public Class<?> getValueClass(Settings settings) {
        try {

		return Address.class;
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	public TypeDefSettingsDefinition[] getTypeDefSettingsDefinitions() {
        try {

		return PointerDataType.dataType.getTypeDefSettingsDefinitions();
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
        try {

		if (dataMgr.isOwnedStrict()) dataMgr.acquireOwnedUnchecked(); else lock.acquire();
		try {
			checkIsValid();

			Address addr = (Address) getValue(buf, settings, length);
			if (addr == null) { // could not create address, so return "Not a pointer (NaP)"
				return NaP;
			}
			return addr.toString();
		}
		finally {
			lock.release();
		}
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	protected boolean isEquivalent(DataType dt, DataTypeConflictHandler handler) {
        try {

		if (dt == null) {
			return false;
		}
		if (this == dt) {
			return true;
		}
		if (!(dt instanceof Pointer)) {
			return false;
		}

		Pointer p = (Pointer) dt;
        DataTypeManagerDB.checkOwnedPointerCopy(p, dataMgr);
		DataType otherDataType = p.getDataType();
		if (hasLanguageDependantLength() != p.hasLanguageDependantLength()) {
			return false;
		}
		if (!hasLanguageDependantLength() && (getLength() != p.getLength())) {
			return false;
		}

		DataType referencedDataType = getDataType();
		if (referencedDataType == null) {
			return otherDataType == null;
		}
		if (otherDataType == null) {
			return false;
		}

		// if they contain datatypes that have same ids, then we are essentially equivalent.
		if (DataTypeUtilities.isSameDataType(referencedDataType, otherDataType)) {
			return true;
		}

		if (!DataTypeUtilities.equalsIgnoreConflict(getDataType().getPathName(),
			otherDataType.getPathName())) {
			return false;
		}

		// NOTE: The pointer deep-dive equivalence checking on the referenced datatype can 
		// cause types containing pointers (composites, functions) to conflict when in
		// reality the referenced type simply has multiple implementations which differ.
		// Although without doing this Ghidra may fail to resolve dependencies which differ
		// from those already contained within a datatype manager.
		// Ghidra's rigid datatype relationships prevent the flexibility to handle 
		// multiple implementations of a named datatype without inducing a conflicted
		// datatype hierarchy.

		if (isEquivalentActive.get()) {
			return true;
		}

		isEquivalentActive.set(true);
		try {
			if (handler != null) {
				handler = handler.getSubsequentHandler();
			}
			return DataTypeDB.isEquivalent(referencedDataType, otherDataType, handler);
		}
		finally {
			isEquivalentActive.set(false);
		}
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	public boolean isEquivalent(DataType dt) {
        try {

		return isEquivalent(dt, null);
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	public void dataTypeReplaced(DataType oldDt, DataType newDt) {
        try {

        if (!deleting) checkOwnedCurrent();
        if (newDt instanceof Pointer pointer && newDt != this)
            DataTypeManagerDB.checkOwnedPointerCopy(pointer, dataMgr);
		if (deleting) {
			return;
		}
		DataTypeUtilities.checkValidReplacement(oldDt, newDt);
		if (dataMgr.isOwnedStrict()) dataMgr.acquireOwnedUnchecked(); else lock.acquire();
		try {
			checkDeleted();
			if (oldDt == getDataType()) {
				if (newDt == this) {
					newDt = DataType.DEFAULT;
				}
				long strictReplacementID = -1;
                if (dataMgr.isOwnedStrict()) {
                    strictReplacementID = dataMgr.resolveOwnedPointerChildID(newDt, null);
                    newDt = dataMgr.getDataType(strictReplacementID);
                }
                // check for existing pointer to newDt
				PointerDataType newPtr = new PointerDataType(newDt,
					hasLanguageDependantLength() ? -1 : getLength(), dataMgr);
				DataType existingPtr =
					dataMgr.getDataType(newDt.getCategoryPath(), newPtr.getName());
				if (existingPtr != null && existingPtr != this) {
					// avoid duplicate pointer - replace this pointer with existing one
					if (dataMgr.isOwnedStrict()) DataTypeManagerDB.checkOwnedPointerCopy((Pointer) existingPtr, dataMgr);
                    dataMgr.addDataTypeToReplace(this, existingPtr);
					return;
				}

				// If newDt pointer not found above revise this pointer which may include category change
				if (!newDt.getCategoryPath().equals(oldDt.getCategoryPath())) {
					// move this pointer to same category as newDt
					try {
						super.setCategoryPath(newDt.getCategoryPath());
					}
					catch (DuplicateNameException e) {
						throw new RuntimeException(e); // already checked
					}
				}

				String myOldName = getOldName();
				oldDt.removeParent(this);
				newDt.addParent(this);

				long replacementID = dataMgr.isOwnedStrict()
                    ? strictReplacementID : dataMgr.getResolvedID(newDt);
                record.setLongValue(PointerDBAdapter.PTR_DT_ID_COL, replacementID);
                try { if (dataMgr.isOwnedStrict()) adapter.updateRecord(record); }
                catch (IOException e) { if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e); throw new ghidra.framework.model.RuntimeIOException(e); }
				refreshName();

				if (!oldDt.getName().equals(newDt.getName())) {
					notifyNameChanged(myOldName);
				}
				try {
					adapter.updateRecord(record);
				}
				catch (IOException e) {
					dataMgr.dbError(e);
				}
			}
		}
		finally {
			lock.release();
		}
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	public void dataTypeDeleted(DataType dt) {
        try {

        if (!deleting) checkOwnedCurrent();
		if (deleting) {
			return;
		}
		if (dataMgr.isOwnedStrict()) dataMgr.acquireOwnedUnchecked(); else lock.acquire();
		try {
			checkDeleted();
			if (dt == getDataType()) {
				dataMgr.addDataTypeToDelete(this, key);
				deleting = true;
			}
		}
		finally {
			lock.release();
		}
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	/**
	 * @see ghidra.program.model.data.DataType#setCategoryPath(ghidra.program.model.data.CategoryPath)
	 *
	 *      Note: this does get called, but in a tricky way. If externally, someone
	 *      calls setCategoryPath, nothing happens because it is overridden in this
	 *      class to do nothing. However, if updatePath is called, then this method
	 *      calls super.setCategoryPath which bypasses the "overriddenness" of
	 *      setCategoryPath, resulting in this method getting called.
	 * 
	 */
	@Override
	protected void doSetCategoryPathRecord(long categoryID) throws IOException {
        try {

        try {

        checkOwnedCurrent();
		record.setLongValue(PointerDBAdapter.PTR_CATEGORY_COL, categoryID);
		adapter.updateRecord(record);
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    
        }
        catch (IOException failure) {
            if (dataMgr.isOwnedStrict()) dataMgr.ownedFailure(failure);
            throw failure;
        }
    }

	@Override
	protected void doSetNameRecord(String newName) throws InvalidNameException {
        try {

		throw new InvalidNameException("Can't set the name of an array!");
		// can't change the name of an pointer
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	public void dataTypeNameChanged(DataType dt, String oldName) {
        try {

		if (deleting) {
			return;
		}
		if (dataMgr.isOwnedStrict()) dataMgr.acquireOwnedUnchecked(); else lock.acquire();
		try {
			checkDeleted();
			if (dt == getDataType()) {
				String myOldName = getOldName();
				refreshName();
				if (!getName().equals(myOldName)) {
					notifyNameChanged(myOldName);
				}
			}
		}
		finally {
			lock.release();
		}
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	public void setName(String name) throws InvalidNameException, DuplicateNameException {
        try {

		// do nothing - can't change the name of a pointer
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	protected void updatePath(DataTypeDB dt) {
        try {

		if (dt == DataTypeUtilities.getBaseDataType(this)) {
			CategoryPath oldPath = getCategoryPath();
			CategoryPath currentPath = dt.getCategoryPath();
			if (!currentPath.equals(oldPath)) {
				try {
					super.setCategoryPath(currentPath);
				}
				catch (DuplicateNameException e) {
					if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
                    // should not happen
				}
			}
		}
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	public void setCategoryPath(CategoryPath path) throws DuplicateNameException {
        try {

		// not permitted to move - follows base type (see updatePath)
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	public boolean dependsOn(DataType dt) {
        try {

		DataType myDt = getDataType();
		return (myDt != null && (myDt == dt || myDt.dependsOn(dt)));
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	public Pointer newPointer(DataType dataType) {
        try {

        checkOwnedCurrent();
        if (dataType instanceof Pointer pointer) DataTypeManagerDB.checkOwnedPointerCopy(pointer, dataMgr);
		if (hasLanguageDependantLength()) {
			return new PointerDataType(dataType, dataMgr);
		}
		return new PointerDataType(dataType, getLength(), dataMgr);
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	public String getDefaultLabelPrefix() {
        try {

		return PointerDataType.POINTER_LABEL_PREFIX;
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	public String getDefaultLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options) {
        try {

		return PointerDataType.getLabelString(buf, settings, getLength(), options);
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	public long getLastChangeTime() {
        try {

		return NO_LAST_CHANGE_TIME;
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	public long getLastChangeTimeInSourceArchive() {
        try {

		return DataType.NO_SOURCE_SYNC_TIME;
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	public UniversalID getUniversalID() {
        try {

		// For now, arrays and pointers don't have UniversalIDs
		return null;
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	protected void setUniversalID(UniversalID id) {
        try {

		// not applicable
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	protected UniversalID getSourceArchiveID() {
        try {

		return DataTypeManager.LOCAL_ARCHIVE_UNIVERSAL_ID;
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	public void setLastChangeTime(long lastChangeTime) {
        try {

		// not applicable
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	public void setLastChangeTimeInSourceArchive(long lastChangeTimeInSourceArchive) {
        try {

		// not applicable
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }

	@Override
	protected void setSourceArchiveID(UniversalID id) {
        try {

		// not applicable
	
        }
        catch (RuntimeException | Error e) {
            if (dataMgr.isOwnedStrict()) throw dataMgr.ownedFailure(e);
            throw e;
        }
    }



    private void requireOwnedMatchingRow(DBRecord current) {
        if (current == null || !current.hasSameSchema(PointerDBAdapter.SCHEMA) ||
            !record.hasSameSchema(PointerDBAdapter.SCHEMA) || current.getKey() != key ||
            record.getKey() != key ||
            current.getLongValue(PointerDBAdapter.PTR_DT_ID_COL) != record.getLongValue(PointerDBAdapter.PTR_DT_ID_COL) ||
            current.getLongValue(PointerDBAdapter.PTR_CATEGORY_COL) != record.getLongValue(PointerDBAdapter.PTR_CATEGORY_COL) ||
            current.getByteValue(PointerDBAdapter.PTR_LENGTH_COL) != record.getByteValue(PointerDBAdapter.PTR_LENGTH_COL))
            throw dataMgr.ownedFailure("Pointer cached/current row mismatch");
    }
    final long readOwnedEdgeChecked(ghidra.util.task.TaskMonitor monitor)
            throws IOException, ghidra.util.exception.CancelledException {
        dataMgr.checkOwnedCancellation(monitor);
        DBRecord current = adapter.getRecord(key);
        dataMgr.checkOwnedCancellation(monitor);
        requireOwnedMatchingRow(current);
        if (isInvalid() || deleting || !checkIsValid()) throw dataMgr.ownedFailure("Stale/deleted pointer");
        return current.getLongValue(PointerDBAdapter.PTR_DT_ID_COL);
    }
    private void checkOwnedCurrent() {
        if (!dataMgr.isOwnedStrict()) return;
        try {
            dataMgr.acquireOwned(ghidra.util.task.TaskMonitor.DUMMY);
            try {
                // Ordinary getters may refresh an unchanged row; observation never calls this first.
                requireOwnedMatchingRow(adapter.getRecord(key));
                if (deleting || !checkIsValid()) throw dataMgr.ownedFailure("Deleted pointer");
                dataMgr.readOwnedPointerEdge(this, ghidra.util.task.TaskMonitor.DUMMY);
            }
            finally { lock.release(); }
        }
        catch (IOException | ghidra.util.exception.CancelledException | RuntimeException | Error e) {
            throw dataMgr.ownedFailure(e);
        }
    }

}
