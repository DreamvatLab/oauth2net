using SimpleInjector;
using SimpleInjector.Advanced;
using System;

namespace shared {
    public static class ContainerFactory
    {
        public static Container CreateWithPropertyInjection<TPropertySelectionBehavior>()
            where TPropertySelectionBehavior : IPropertySelectionBehavior
        {
            var r = new Container();
            r.Options.PropertySelectionBehavior = Activator.CreateInstance<TPropertySelectionBehavior>();
            return r;
        }
    }
}
