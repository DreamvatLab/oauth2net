using SimpleInjector.Advanced;
using System;
using System.Composition;
using System.Linq;
using System.Reflection;

namespace shared {
    public class ImportPropertySelectionBehavior : IPropertySelectionBehavior
    {
        public bool SelectProperty(Type implementationType, PropertyInfo prop) =>
            prop.GetCustomAttributes(typeof(ImportAttribute)).Any();
    }
}
