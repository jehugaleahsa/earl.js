# UrlTemplate

This is an initial draft of a project to allow you to extract values from URLs and create URLs from a template.

## Working with a Template
Whether extracting values or creating URLs, you start with a URL template, using curly braces to indicate placeholders.

    var template = UrlTemplate.parse('http://www.example.com/customers/{customerId}');
	
From here, you can extract the `customerId` value from an actual URL.

	var params = template.extract('http://www.example.com/customers/123');
	var customerId = parseInt(params.customerId, 10);
	
Or, you can generate a URL by passing an object.

	var url = template.format({ customerId: 123 });
	
## Query Strings
Currently, if you call `extract`, any query string parameters will be added to the returned object. If there is a naming conflict, a path variable takes precedence over query string keys.

If you call `format` with unmatched key/value pairs, the remaining pairs are added to the URL's query string.

## Upcoming Changes
I would like to give the project a better name. I would also like to expose this library as a single function that returns a template. Writing `UrlTemplate.parse` is awkward and verbose.

I plan on adding unit tests and automating builds using Node.js and either grunt.js or gulp.js.

I plan on changing the code so that it doesn't add members to the global namespace.

Eventually, I would like to add type annotations to placeholders. When `extract`-ing values, these would be used to perform automatic type conversion. The same annotations could be used during URL creation.

I might consider changing the code to deal with query strings explicitly. This would mean coming up with a notation. Query strings are a bit tricky because their order _shouldn't_ matter. I also don't want to require you to explicitly include `?` or `&` symbols. It should also be possible to mark some query string pairs as optional (or even specify default values).