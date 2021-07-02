package org.openjump.core.ui.plugin.datastore.ocient;

import com.vividsolutions.jump.datastore.DataStoreDriver;
import com.vividsolutions.jump.workbench.plugin.AbstractPlugIn;
import com.vividsolutions.jump.workbench.plugin.PlugInContext;
import java.sql.Driver;
/**
 * @author potocki
 */
public class OcientDatastorePlugIn extends AbstractPlugIn {

    public OcientDatastorePlugIn() {
    }

    public void initialize(PlugInContext context) throws Exception {
        try {
            context.getWorkbenchContext().getRegistry().createEntry(DataStoreDriver.REGISTRY_CLASSIFICATION,
                new OcientDataStoreDriver());
            System.out.println("Ocient Data Store added");
        } catch (Exception e) {
            System.out.println("Ocient driver not found: " + e.toString() + ". Ocient Data Store NOT added");
        }

    }
}